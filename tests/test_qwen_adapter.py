"""qwen-code Hook 适配器测试。

驱动数据是 0.27.2 实测录制（tests/fixtures/hooks/qwen-code/0.27.2/），不是
官方文档推断。锁定四件事：

1. 三个实测事件的字段映射正确，timestamp 能变成事件时间；
2. 未实测的事件（SessionEnd）与新增字段一律明确失败，不静默忽略；
3. deny 渲染成 stdout 决策，ask 不渲染（未测过就不发产品可能忽略的指令）；
4. 能力矩阵只声明测过的部分：三个事件、PreToolUse 有 deny 无 confirm。
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from adapters.products import HookDirective, QwenCodeAdapter
from adapters.products.capabilities import PRODUCT_CAPABILITIES
from domain import CapabilityVerification, HookCapability, HookEventType, IntentDecision
from products.registry import ProductCatalog

FIXTURES = Path(__file__).parent / "fixtures" / "hooks" / "qwen-code" / "0.26.8"
VERSIONS = ("0.26.8", "0.27.2")
ADAPTER = QwenCodeAdapter()


def load(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


def test_session_start_maps_with_recorded_event_time():
    payload = load("SessionStart")
    event = ADAPTER.parse_hook_input(payload)
    assert event.hook_event_type is HookEventType.SESSION_START
    assert event.session_id == payload["session_id"]
    # qwen-code 提供 timestamp，因此事件时间来自产品而不是端侧接收时间。
    assert event.occurred_at is not None
    assert event.occurred_at.year == 2026
    assert event.tool_name is None and event.params == {}


def test_pre_tool_use_maps_tool_and_params():
    payload = load("PreToolUse")
    event = ADAPTER.parse_hook_input(payload)
    assert event.hook_event_type is HookEventType.PRE_TOOL_USE
    assert event.tool_name == payload["tool_name"]
    assert event.params == payload["tool_input"]
    assert event.tool_call_id == payload["tool_use_id"]
    assert event.product_result is None


def test_post_tool_use_compacts_structured_response():
    payload = load("PostToolUse")
    event = ADAPTER.parse_hook_input(payload)
    assert event.hook_event_type is HookEventType.POST_TOOL_USE
    # tool_response 是结构化对象（llmContent/returnDisplay），进中性事件前压成 JSON 串。
    assert isinstance(event.product_result, str)
    assert event.product_result.startswith("{")
    assert payload["tool_response"]["returnDisplay"] in event.product_result


def test_session_end_is_rejected_because_unrecorded():
    payload = load("SessionStart")
    payload["hook_event_name"] = "SessionEnd"
    with pytest.raises(ValueError, match="未声明或未实测"):
        ADAPTER.parse_hook_input(payload)


def test_unknown_field_is_rejected_not_ignored():
    payload = load("PreToolUse")
    payload["new_telemetry"] = "x"
    with pytest.raises(ValueError, match="未声明的字段"):
        ADAPTER.parse_hook_input(payload)


def test_invalid_timestamp_fails_explicitly():
    payload = load("PreToolUse")
    payload["timestamp"] = "not-a-time"
    with pytest.raises(ValueError, match="ISO8601"):
        ADAPTER.parse_hook_input(payload)


def test_tool_input_must_be_object():
    payload = load("PreToolUse")
    payload["tool_input"] = "command=ls"
    with pytest.raises(ValueError, match="tool_input 必须是对象"):
        ADAPTER.parse_hook_input(payload)


def test_deny_renders_stdout_permission_decision():
    event = ADAPTER.parse_hook_input(load("PreToolUse"))
    response = ADAPTER.render_directive(event, HookDirective(IntentDecision.DENY, "blocked"))
    assert response.exit_code == 0            # 不用 exit 2，避免误伤与 stderr 回喂
    payload = json.loads(response.stdout)
    assert payload["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert payload["hookSpecificOutput"]["permissionDecisionReason"] == "blocked"


def test_ask_is_not_rendered_because_unmeasured():
    event = ADAPTER.parse_hook_input(load("PreToolUse"))
    response = ADAPTER.render_directive(event, HookDirective(IntentDecision.ASK, "confirm?"))
    # ask 未实测，宁可不发指令：发一个产品可能忽略的 ask 会把"未拦截"伪装成"已确认"。
    assert response.stdout == "" and response.exit_code == 0


def test_post_event_is_forced_to_observe():
    event = ADAPTER.parse_hook_input(load("PostToolUse"))
    response = ADAPTER.render_directive(event, HookDirective(IntentDecision.DENY, "too late"))
    assert response.exit_code == 0 and response.stdout == ""


def test_capabilities_claim_only_measured_surface():
    descriptor = PRODUCT_CAPABILITIES["qwen-code"]
    assert descriptor.product_version == "0.26.8"
    events = {cap.hook_event_type: cap for cap in descriptor.events}
    assert set(events) == {HookEventType.SESSION_START, HookEventType.PRE_TOOL_USE,
                           HookEventType.POST_TOOL_USE}
    # SessionEnd 未捕获，不得出现在能力矩阵里。
    assert HookEventType.SESSION_END not in events
    pre = events[HookEventType.PRE_TOOL_USE]
    assert pre.pre_execution is True
    assert HookCapability.DENY in pre.capabilities
    assert HookCapability.CONFIRM not in pre.capabilities
    assert pre.verification is CapabilityVerification.VERIFIED
    assert pre.evidence_ref.endswith("qwen-code/0.26.8/PreToolUse.json")
    assert "prompt_id" in descriptor.unsupported_fields


def test_registry_exposes_three_products():
    catalog = ProductCatalog()
    assert catalog.ids() == ["claude-code", "codex", "qwen-code"]
    assert catalog.descriptor("qwen-code").collector_id == "qwen-code-hook-v1"


@pytest.mark.parametrize("version", VERSIONS)
def test_both_recorded_versions_parse_with_the_same_adapter(version):
    """0.26.8 与 0.27.2 的抓包字段集一致，同一份字段表能解析两版。

    这不是说"版本无关"：能力门控仍按 0.26.8（设备实版本）。这条只证明协议
    形状没变，所以适配器不必为 0.27.2 单独维护一份字段表；哪天形状变了，
    这里会先红，而不是等到端侧上报被拒才发现。
    """
    directory = Path(__file__).parent / "fixtures" / "hooks" / "qwen-code" / version
    for name, expected in (
        ("SessionStart", HookEventType.SESSION_START),
        ("PreToolUse", HookEventType.PRE_TOOL_USE),
        ("PostToolUse", HookEventType.POST_TOOL_USE),
    ):
        payload = json.loads((directory / f"{name}.json").read_text(encoding="utf-8"))
        assert ADAPTER.parse_hook_input(payload).hook_event_type is expected
