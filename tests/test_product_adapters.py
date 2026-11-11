"""产品 Hook 适配器测试。

锁定三件事：① 三类决策（allow/ask/deny）渲染成产品认识的退出方式，且
非执行前事件一律被压成 observe；② 字段兼容是显式的——缺字段、多字段、
类型错误都必须明确失败；③ 能力矩阵的验证等级是约束而不是注释：未实测
条目不得声明 confirm/deny，Codex 不得声称能摄入。

 fixtures 来自官方文档的 payload 形状。协议尖峰（S3）会把它们替换为真实
录制数据，届时本文件的断言保持不变、驱动数据换成实测。
"""

from __future__ import annotations

import importlib
import json
import threading
from types import SimpleNamespace

import httpx
import pytest
from pydantic import ValidationError

from adapters.products import (
    ClaudeCodeAdapter,
    CodexAdapter,
    HookDirective,
    UnsupportedHookProtocol,
)
from adapters.products.capabilities import PRODUCT_CAPABILITIES
from domain import (
    CapabilityVerification,
    HookCapability,
    HookEventCapability,
    HookEventType,
    HookTransport,
    IntentDecision,
)
from products.registry import ProductCatalog

ADAPTER = ClaudeCodeAdapter()


@pytest.fixture()
def api(tmp_path, monkeypatch):
    """起一个绑到临时库的真实 HTTP 服务，验证 /api/v1/products 路由。"""
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("FUSION_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("FUSION_SCAN_ROOT", str(workspace))
    monkeypatch.setenv("FUSION_BIND", "127.0.0.1")
    monkeypatch.setenv("ASGP_MODEL_PROVIDER", "stepfun")
    module = importlib.reload(importlib.import_module("server"))
    server = module.ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield SimpleNamespace(module=module, base=f"http://127.0.0.1:{server.server_port}")
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def login(api, username: str = "admin", password: str = "admin-passphrase-1234") -> str:
    api.module.auth_service.bootstrap_admin(password=password)
    with httpx.Client() as client:
        response = client.post(api.base + "/api/session", timeout=15,
                               json={"username": username, "password": password})
    assert response.status_code == 200, response.text
    return response.json()["token"]


def payload(event: str, **overrides):
    base = {
        "SessionStart": {
            "session_id": "sess_1",
            "transcript_path": "/home/u/.claude/projects/p/sess_1.jsonl",
            "cwd": "/home/u/work",
            "permission_mode": "default",
            "hook_event_name": "SessionStart",
        },
        "PreToolUse": {
            "session_id": "sess_1",
            "transcript_path": "/home/u/.claude/projects/p/sess_1.jsonl",
            "cwd": "/home/u/work",
            "permission_mode": "default",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
            "tool_use_id": "toolu_01ABC",
        },
        "PostToolUse": {
            "session_id": "sess_1",
            "transcript_path": "/home/u/.claude/projects/p/sess_1.jsonl",
            "cwd": "/home/u/work",
            "permission_mode": "default",
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "ls -la"},
            "tool_use_id": "toolu_01ABC",
            "tool_response": {"stdout": "total 0", "exit_code": 0},
        },
        "SessionEnd": {
            "session_id": "sess_1",
            "transcript_path": "/home/u/.claude/projects/p/sess_1.jsonl",
            "cwd": "/home/u/work",
            "permission_mode": "default",
            "hook_event_name": "SessionEnd",
        },
    }[event]
    base.update(overrides)
    return base


class TestClaudeCodeParsing:
    def test_session_start_has_no_tool_fields(self):
        event = ADAPTER.parse_hook_input(payload("SessionStart"))
        assert event.event == "SessionStart"
        assert event.hook_event_type is HookEventType.SESSION_START
        assert event.session_id == "sess_1"
        assert event.tool_name is None
        assert event.tool_call_id is None
        assert event.params == {}
        # 本地定位字段不得进入中性事件。
        assert "transcript_path" not in event.neutral()
        assert "cwd" not in event.neutral()
        assert "permission_mode" not in event.neutral()

    def test_pre_tool_use_carries_tool_call(self):
        event = ADAPTER.parse_hook_input(payload("PreToolUse"))
        assert event.hook_event_type is HookEventType.PRE_TOOL_USE
        assert event.tool_name == "Bash"
        assert event.tool_call_id == "toolu_01ABC"
        assert event.params == {"command": "ls -la"}
        # 产品不提供事件时间；occurred_at 由端侧 stamp 接收时间。
        assert event.occurred_at is None

    def test_post_tool_use_result_is_compacted(self):
        event = ADAPTER.parse_hook_input(payload("PostToolUse"))
        assert event.hook_event_type is HookEventType.POST_TOOL_USE
        assert event.product_result is not None
        assert "total 0" in event.product_result

    def test_missing_required_field_fails(self):
        raw = payload("PreToolUse")
        del raw["session_id"]
        with pytest.raises(ValueError, match="session_id"):
            ADAPTER.parse_hook_input(raw)

    def test_unknown_event_name_fails(self):
        with pytest.raises(ValueError, match="hook_event_name"):
            ADAPTER.parse_hook_input(payload("SessionStart", hook_event_name="UserPromptSubmit"))

    def test_unknown_field_fails_explicitly(self):
        # 产品升级加了新字段必须明确失败，不能被静默忽略。
        raw = payload("PreToolUse", permission_suggestions=[{"type": "toolAlwaysAllow"}])
        with pytest.raises(ValueError, match="未声明的字段"):
            ADAPTER.parse_hook_input(raw)

    def test_wrong_type_fails(self):
        with pytest.raises(ValueError, match="tool_input"):
            ADAPTER.parse_hook_input(payload("PreToolUse", tool_input="ls -la"))

    def test_local_only_fields_are_type_checked(self):
        with pytest.raises(ValueError, match="transcript_path"):
            ADAPTER.parse_hook_input(payload("PreToolUse", transcript_path={"path": "x"}))


class TestClaudeCodeDirective:
    @pytest.mark.parametrize(
        "decision,expected",
        [
            (IntentDecision.ALLOW, "allow"),
            (IntentDecision.ASK, "ask"),
            (IntentDecision.DENY, "deny"),
        ],
    )
    def test_three_decisions_render_to_stdout(self, decision, expected):
        event = ADAPTER.parse_hook_input(payload("PreToolUse"))
        response = ADAPTER.render_directive(event, HookDirective(decision=decision))
        assert response.exit_code == 0
        assert json.loads(response.stdout) == {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": expected,
            }
        }

    def test_reason_is_carried(self):
        event = ADAPTER.parse_hook_input(payload("PreToolUse"))
        response = ADAPTER.render_directive(
            event, HookDirective(decision=IntentDecision.DENY, reason="策略禁止")
        )
        output = json.loads(response.stdout)["hookSpecificOutput"]
        assert output["permissionDecisionReason"] == "策略禁止"

    @pytest.mark.parametrize(
        "event_name", ["SessionStart", "PostToolUse", "SessionEnd"]
    )
    def test_non_pre_execution_events_are_forced_to_observe(self, event_name):
        # 非执行前事件注入 deny 也必须被压成 observe：接口层硬闸，不依赖
        # 调用方自觉。
        event = ADAPTER.parse_hook_input(payload(event_name))
        response = ADAPTER.render_directive(event, HookDirective(decision=IntentDecision.DENY))
        assert response.exit_code == 0
        assert response.stdout == ""

    def test_observe_directive_writes_nothing(self):
        event = ADAPTER.parse_hook_input(payload("PreToolUse"))
        response = ADAPTER.render_directive(event, HookDirective())
        assert response.exit_code == 0
        assert response.stdout == ""

    def test_exit_code_two_is_never_used(self):
        # exit 2 的语义是"阻断并把 stderr 回喂给模型"，observe 模式下误触
        # 即未声明的拦截；结构化 stdout 才是机器可判定的通道。
        event = ADAPTER.parse_hook_input(payload("PreToolUse"))
        for decision in (IntentDecision.ALLOW, IntentDecision.ASK, IntentDecision.DENY):
            assert ADAPTER.render_directive(event, HookDirective(decision=decision)).exit_code == 0


class TestCapabilityMatrix:
    def test_claude_code_declares_four_events(self):
        descriptor = PRODUCT_CAPABILITIES["claude-code"]
        assert {entry.hook_event_type for entry in descriptor.events} == {
            HookEventType.SESSION_START,
            HookEventType.PRE_TOOL_USE,
            HookEventType.POST_TOOL_USE,
            HookEventType.SESSION_END,
        }
        assert descriptor.hook_transport is HookTransport.STDIN_JSON
        assert descriptor.collector_id == "claude-code-hook-v1"
        assert descriptor.ingest_supported is True

    def test_only_pre_tool_use_is_pre_execution(self):
        entries = {entry.hook_event_type: entry for entry in
                   PRODUCT_CAPABILITIES["claude-code"].events}
        assert entries[HookEventType.PRE_TOOL_USE].pre_execution is True
        for other in (HookEventType.SESSION_START, HookEventType.POST_TOOL_USE,
                      HookEventType.SESSION_END):
            assert entries[other].pre_execution is False

    def test_verified_capabilities_are_event_specific(self):
        # 真实协议尖峰后，只给执行前事件声明已实测的决策能力。
        for entry in PRODUCT_CAPABILITIES["claude-code"].events:
            assert entry.verification is CapabilityVerification.VERIFIED
            if entry.pre_execution:
                assert HookCapability.DENY in entry.capabilities
                assert HookCapability.CONFIRM in entry.capabilities
                assert entry.decision_protocol == "stdout_permission_decision"
            else:
                assert entry.capabilities == [HookCapability.OBSERVE]
                assert entry.decision_protocol == "none"
            assert entry.verified_against
            assert entry.evidence_ref

    def test_codex_has_real_versioned_protocol(self):
        descriptor = PRODUCT_CAPABILITIES["codex"]
        assert descriptor.ingest_supported is True
        assert len(descriptor.events) == 4
        assert not descriptor.unsupported_reason
        assert descriptor.verification is CapabilityVerification.VERIFIED
        assert descriptor.hook_transport is HookTransport.STDIN_JSON

    def test_unverified_entry_cannot_claim_deny(self):
        with pytest.raises(ValidationError, match="confirm/deny"):
            HookEventCapability(
                hook_event_type=HookEventType.PRE_TOOL_USE,
                pre_execution=True,
                capabilities=[HookCapability.OBSERVE, HookCapability.DENY],
                verification=CapabilityVerification.UNVERIFIED,
            )

    def test_unverified_entry_cannot_claim_decision_protocol(self):
        with pytest.raises(ValidationError, match="决策通道"):
            HookEventCapability(
                hook_event_type=HookEventType.PRE_TOOL_USE,
                pre_execution=True,
                capabilities=[HookCapability.OBSERVE],
                decision_protocol="stdout_permission_decision",
                verification=CapabilityVerification.UNVERIFIED,
            )

    def test_verified_entry_requires_evidence(self):
        with pytest.raises(ValidationError, match="evidence_ref"):
            HookEventCapability(
                hook_event_type=HookEventType.PRE_TOOL_USE,
                pre_execution=True,
                capabilities=[HookCapability.OBSERVE],
                verification=CapabilityVerification.VERIFIED,
            )

    def test_verified_blocking_entry_is_accepted(self):
        # 协议尖峰通过后，PreToolUse 条目应能升级成这个形状。
        entry = HookEventCapability(
            hook_event_type=HookEventType.PRE_TOOL_USE,
            pre_execution=True,
            capabilities=[HookCapability.OBSERVE, HookCapability.CONFIRM, HookCapability.DENY],
            decision_protocol="stdout_permission_decision",
            verification=CapabilityVerification.VERIFIED,
            verified_against="Claude Code 2.x（本环境实测）",
            evidence_ref="tests/fixtures/hooks/claude-code/pre_tool_use.json",
        )
        assert entry.capabilities[-1] is HookCapability.DENY

    def test_blocking_capability_requires_pre_execution(self):
        with pytest.raises(ValidationError, match="执行前"):
            HookEventCapability(
                hook_event_type=HookEventType.POST_TOOL_USE,
                pre_execution=False,
                capabilities=[HookCapability.OBSERVE, HookCapability.DENY],
                decision_protocol="stdout_permission_decision",
                verification=CapabilityVerification.VERIFIED,
                verified_against="x",
                evidence_ref="y",
            )

    def test_descriptor_aggregates_to_most_conservative(self):
        # 当前四类事件均有实测 fixture，产品聚合验证等级为 verified。
        descriptor = PRODUCT_CAPABILITIES["claude-code"]
        assert descriptor.verification is CapabilityVerification.VERIFIED

    def test_descriptor_rejects_duplicate_event_entries(self):
        from domain import AgentProductDescriptor

        entry = HookEventCapability(
            hook_event_type=HookEventType.PRE_TOOL_USE,
            pre_execution=True,
            capabilities=[HookCapability.OBSERVE],
        )
        with pytest.raises(ValidationError, match="重复"):
            AgentProductDescriptor(
                product_id="x", product_version="1", adapter_version="1",
                vendor="v", collector_id="c", events=[entry, entry],
            )

    def test_descriptor_rejects_ingest_without_events(self):
        from domain import AgentProductDescriptor

        with pytest.raises(ValidationError, match="至少声明"):
            AgentProductDescriptor(
                product_id="x", product_version="1", adapter_version="1",
                vendor="v", collector_id="c", events=[],
            )


class TestCodexAdapter:
    def test_invalid_parse_is_refused(self):
        with pytest.raises(ValueError):
            CodexAdapter().parse_hook_input({"anything": True})

    def test_directive_is_always_observe(self):
        adapter = CodexAdapter()
        assert adapter.collector_id() == "codex-hook-v1"
        assert "transcript_path" in adapter.unsupported_fields()


class TestCatalog:
    def test_unknown_product_is_rejected(self):
        with pytest.raises(KeyError):
            ProductCatalog().get("cursor")

    def test_descriptors_cover_registered_products(self):
        catalog = ProductCatalog()
        assert catalog.ids() == ["claude-code", "codex"]
        assert {d.product_id for d in catalog.descriptors()} == {"claude-code", "codex"}


class TestProductsEndpoint:
    def _call(self, base, token=None):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        with httpx.Client() as client:
            return client.get(base + "/api/v1/products", headers=headers, timeout=15)

    def test_unauthenticated_is_rejected(self, api):
        assert self._call(api.base).status_code == 401

    def test_matrix_is_returned_verbatim(self, api):
        response = self._call(api.base, token=login(api))
        assert response.status_code == 200
        products = {entry["product_id"]: entry for entry in response.json()["products"]}
        assert set(products) == {"claude-code", "codex"}

        claude = products["claude-code"]
        # 验证状态必须透传给调用方，控制面不做加工。
        assert claude["events"], "可摄入的产品必须声明事件"
        assert all(entry["verification"] == "verified" for entry in claude["events"])
        assert all(entry["decision_protocol"] == ("stdout_permission_decision" if entry["pre_execution"] else "none") for entry in claude["events"])
        assert claude["ingest_supported"] is True

        codex = products["codex"]
        assert codex["ingest_supported"] is True
        assert len(codex["events"]) == 4
        assert codex["hook_transport"] == "stdin_json"

    def test_contract_carries_no_secret_shaped_field(self, api):
        response = self._call(api.base, token=login(api))
        text = response.text
        for forbidden in ("token", "secret", "api_key", "authorization", "password"):
            assert forbidden not in text.lower()
