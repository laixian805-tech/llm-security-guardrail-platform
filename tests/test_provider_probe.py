"""Provider Probe 与 wire API 区分测试。

覆盖：Probe 成功只回传状态/延迟/协议/能力；candidate 未通过 Probe 不进入
默认路由；Codex Responses 与扫描器 Chat Completions 分别 Probe；密钥不出
现在结果、错误文本和路由决策里。
"""

from __future__ import annotations

import json

import httpx
import pytest

from domain import ModelProviderProfile, ProbeStatus, ProviderRole, WireApi, WireProfile
from model_providers import (
    provider_catalog,
    resolve_wire_profile,
    routing_decision,
    scanner_provider_environment,
)
from services.provider_probe import ProviderProbeService, normalize_wire_api
from storage.repositories import Storage

STEPFUN_KEY = "sk-stepfun-secret-value-0001"
XUNFEI_KEY = "xf-password-secret-value-0002"


@pytest.fixture(autouse=True)
def provider_env(tmp_path, monkeypatch):
    codex = tmp_path / "config.toml"
    codex.write_text(
        'model = "step-5-preview"\n'
        'model_provider = "stepfun"\n'
        "\n"
        "[model_providers.stepfun]\n"
        'base_url = "https://api.stepfun.com/step_plan/v1"\n'
        'wire_api = "responses"\n'
        "[model_providers.stepfun.http_headers]\n"
        f'Authorization = "Bearer {STEPFUN_KEY}"\n'
        "\n"
        "[model_providers.xunfei]\n"
        'base_url = "https://maas-api.cn-huabei-1.xf-yun.com/v1"\n'
        'wire_api = "responses"\n'
        "[model_providers.xunfei.http_headers]\n"
        f'Authorization = "Bearer {XUNFEI_KEY}"\n',
        encoding="utf-8",
    )
    monkeypatch.setenv("CODEX_CONFIG_PATH", str(codex))
    monkeypatch.setenv("STEPFUN_API_KEY", STEPFUN_KEY)
    monkeypatch.setenv("STEPFUN_MODEL", "step-5-preview")
    monkeypatch.setenv("STEPFUN_CHAT_BASE_URL", "https://api.stepfun.com/v1")
    # Codex profile 的模型必须显式指定，不从顶层 model 推断。
    monkeypatch.setenv("STEPFUN_CODEX_MODEL", "step-5-preview")
    monkeypatch.setenv("XUNFEI_API_PASSWORD", XUNFEI_KEY)
    monkeypatch.setenv("XUNFEI_MODEL", "spark-4.0")
    monkeypatch.setenv("XUNFEI_CHAT_BASE_URL", "https://maas-api.cn-huabei-1.xf-yun.com/v1")
    monkeypatch.setenv("XUNFEI_CODEX_MODEL", "spark-4.0")
    monkeypatch.delenv("ASGP_MODEL_PROVIDER", raising=False)


def service(storage: Storage, handler) -> ProviderProbeService:
    return ProviderProbeService(storage=storage, transport=httpx.MockTransport(handler))


def chat_completions_ok(model: str = "step-5-preview") -> httpx.Response:
    return httpx.Response(200, json={
        "id": "cmpl-probe", "object": "chat.completion", "model": model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": "{}"},
                     "finish_reason": "length"}],
    })


def responses_ok(model: str = "step-5-preview") -> httpx.Response:
    return httpx.Response(200, json={
        "id": "resp-probe", "object": "response", "model": model,
        "output": [{"type": "message", "role": "assistant",
                    "content": [{"type": "output_text", "text": "{}"}]}],
    })


class TestWireApiSeparation:
    def test_scanner_and_codex_profiles_are_distinct(self):
        scanner = resolve_wire_profile("stepfun", "scanner")
        codex = resolve_wire_profile("stepfun", "codex")
        assert scanner["wire_api"] == "chat_completions"
        assert codex["wire_api"] == "responses"
        assert scanner["base_url"] != codex["base_url"], "同一供应商的两条 profile 不能合并 endpoint"
        assert scanner["base_url"] == "https://api.stepfun.com/v1"
        assert codex["base_url"] == "https://api.stepfun.com/step_plan/v1"

    def test_profiles_are_probed_independently(self, tmp_path):
        storage = Storage(tmp_path / "p.db")
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(str(request.url))
            if str(request.url).endswith("/chat/completions"):
                return chat_completions_ok()
            return responses_ok()

        svc = service(storage, handler)
        scanner = svc.probe(provider_id="stepfun", profile_kind="scanner")
        codex = svc.probe(provider_id="stepfun", profile_kind="codex")

        assert scanner["status"] == "passed"
        assert codex["status"] == "passed"
        assert scanner["wire_api"] == "chat_completions"
        assert codex["wire_api"] == "responses"
        assert svc.status_for("stepfun", "scanner") == "passed"
        assert svc.status_for("stepfun", "codex") == "passed"
        assert len(seen) == 2

    def test_passing_one_profile_does_not_pass_the_other(self, tmp_path):
        storage = Storage(tmp_path / "p.db")
        svc = service(storage, lambda request: chat_completions_ok())
        assert svc.probe(provider_id="stepfun", profile_kind="scanner")["status"] == "passed"
        assert svc.status_for("stepfun", "codex") == "unknown"

    def test_normalize_wire_api_variants(self):
        assert normalize_wire_api("responses") == "responses"
        assert normalize_wire_api("chat.completions") == "chat_completions"
        assert normalize_wire_api("chat_completions") == "chat_completions"
        assert normalize_wire_api("Chat-Completions") == "chat_completions"
        assert normalize_wire_api("weird") == "weird"

    def test_codex_model_must_be_declared_explicitly(self, monkeypatch):
        """不从 Codex 顶层 model 推断：那个模型属于当前 model_provider。"""
        monkeypatch.delenv("STEPFUN_CODEX_MODEL", raising=False)
        assert resolve_wire_profile("stepfun", "codex")["model"] == ""
        assert resolve_wire_profile("stepfun", "codex")["configured"] is False

    def test_codex_model_can_be_overridden_by_env(self, monkeypatch):
        monkeypatch.setenv("STEPFUN_CODEX_MODEL", "override-model")
        assert resolve_wire_profile("stepfun", "codex")["model"] == "override-model"

    def test_codex_profile_without_model_is_not_configured(self, monkeypatch):
        monkeypatch.delenv("STEPFUN_CODEX_MODEL", raising=False)
        assert resolve_wire_profile("stepfun", "codex")["configured"] is False

    def test_responses_probe_uses_flat_tool_schema(self, tmp_path):
        """Responses API 不接受 Chat Completions 的 function 嵌套工具 schema。"""
        storage = Storage(tmp_path / "p.db")
        captured: dict[str, object] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            import json as _json
            captured["body"] = _json.loads(request.content)
            return responses_ok()

        svc = service(storage, handler)
        assert svc.probe(provider_id="stepfun", profile_kind="codex")["status"] == "passed"

        tool = captured["body"]["tools"][0]
        assert tool["type"] == "function"
        assert "function" not in tool, "Responses 用扁平 schema，不能嵌套 function"
        assert tool["name"] == "probe_ping"
        assert "parameters" in tool

    def test_chat_completions_probe_uses_nested_tool_schema(self, tmp_path):
        storage = Storage(tmp_path / "p.db")
        captured: dict[str, object] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            import json as _json
            captured["body"] = _json.loads(request.content)
            return chat_completions_ok()

        svc = service(storage, handler)
        assert svc.probe(provider_id="stepfun", profile_kind="scanner")["status"] == "passed"

        tool = captured["body"]["tools"][0]
        assert tool["type"] == "function"
        assert tool["function"]["name"] == "probe_ping"


class TestProbeResult:
    def test_pass_reports_only_status_latency_protocol_capabilities(self, tmp_path):
        storage = Storage(tmp_path / "p.db")
        svc = service(storage, lambda request: chat_completions_ok())
        result = svc.probe(provider_id="stepfun", profile_kind="scanner")

        assert result["status"] == "passed"
        assert result["http_status"] == 200
        assert isinstance(result["latency_ms"], int) and result["latency_ms"] >= 0
        assert result["model_echoed"] == "step-5-preview"
        assert result["capabilities"] == ["structured_output", "tool_calling"]
        assert result["error"] is None
        assert result["error_kind"] is None

    def test_result_never_contains_the_key(self, tmp_path):
        storage = Storage(tmp_path / "p.db")
        svc = service(storage, lambda request: chat_completions_ok())
        result = svc.probe(provider_id="stepfun", profile_kind="scanner")
        blob = json.dumps(result, ensure_ascii=False)
        assert STEPFUN_KEY not in blob

    def test_key_only_travels_in_the_authorization_header(self, tmp_path):
        storage = Storage(tmp_path / "p.db")
        captured: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["authorization"] = request.headers.get("authorization", "")
            captured["url"] = str(request.url)
            return chat_completions_ok()

        svc = service(storage, handler)
        svc.probe(provider_id="stepfun", profile_kind="scanner")
        assert captured["authorization"] == f"Bearer {STEPFUN_KEY}"
        assert STEPFUN_KEY not in captured["url"], "密钥不得进入 URL"

    def test_error_text_is_redacted(self, tmp_path):
        storage = Storage(tmp_path / "p.db")

        def handler(request: httpx.Request) -> httpx.Response:
            # 上游把密钥回显到错误体里；结果和错误文本都不能带出它。
            return httpx.Response(401, json={"error": {"message": f"bad key {STEPFUN_KEY}"}})

        svc = service(storage, handler)
        result = svc.probe(provider_id="stepfun", profile_kind="scanner")
        assert result["status"] == "failed"
        assert result["error_kind"] == "unauthorized"
        # 401 不回传上游错误体，密钥从一开始就不进入结果。
        assert STEPFUN_KEY not in json.dumps(result, ensure_ascii=False)

    def test_propagated_upstream_error_is_redacted(self, tmp_path):
        storage = Storage(tmp_path / "p.db")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, json={"error": {"message": f"boom for {STEPFUN_KEY}"}})

        svc = service(storage, handler)
        result = svc.probe(provider_id="stepfun", profile_kind="scanner")
        assert result["status"] == "failed"
        assert result["error_kind"] == "http_error"
        assert STEPFUN_KEY not in json.dumps(result, ensure_ascii=False)
        assert "***" in result["error"], "回传的上游错误必须先抹掉密钥"

    def test_stored_probe_row_never_contains_the_key(self, tmp_path):
        storage = Storage(tmp_path / "p.db")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"error": {"message": f"bad key {STEPFUN_KEY}"}})

        svc = service(storage, handler)
        svc.probe(provider_id="stepfun", profile_kind="scanner")
        with storage.connection() as conn:
            blob = " ".join(str(value) for row in conn.execute("SELECT * FROM provider_probes")
                            for value in tuple(row))
        assert STEPFUN_KEY not in blob

    def test_timeout_maps_to_failed(self, tmp_path):
        storage = Storage(tmp_path / "p.db")

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("too slow", request=request)

        svc = service(storage, handler)
        result = svc.probe(provider_id="stepfun", profile_kind="scanner")
        assert result["status"] == "failed"
        assert result["error_kind"] == "timeout"
        assert result["http_status"] is None

    def test_unreachable_maps_to_failed(self, tmp_path):
        storage = Storage(tmp_path / "p.db")

        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused", request=request)

        svc = service(storage, handler)
        result = svc.probe(provider_id="stepfun", profile_kind="scanner")
        assert result["status"] == "failed"
        assert result["error_kind"] == "unreachable"
        assert STEPFUN_KEY not in json.dumps(result, ensure_ascii=False)

    def test_protocol_mismatch_maps_to_failed(self, tmp_path):
        storage = Storage(tmp_path / "p.db")
        svc = service(storage, lambda request: httpx.Response(200, json={"unexpected": True}))
        result = svc.probe(provider_id="stepfun", profile_kind="scanner")
        assert result["status"] == "failed"
        assert result["error_kind"] == "protocol_mismatch"

    def test_model_mismatch_maps_to_failed(self, tmp_path):
        storage = Storage(tmp_path / "p.db")
        svc = service(storage, lambda request: chat_completions_ok(model="some-other-model"))
        result = svc.probe(provider_id="stepfun", profile_kind="scanner")
        assert result["status"] == "failed"
        assert result["error_kind"] == "model_mismatch"
        assert "step-5-preview" in result["error"] and "some-other-model" in result["error"]

    def test_capability_rejection_maps_to_failed(self, tmp_path):
        storage = Storage(tmp_path / "p.db")

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(400, json={"error": {
                "message": "unsupported parameter: response_format", "type": "invalid_request_error"}})

        svc = service(storage, handler)
        result = svc.probe(provider_id="stepfun", profile_kind="scanner")
        assert result["status"] == "failed"
        assert result["error_kind"] == "capability_rejected"

    def test_plain_http_error_maps_to_failed(self, tmp_path):
        storage = Storage(tmp_path / "p.db")
        svc = service(storage, lambda request: httpx.Response(500, json={"error": "boom"}))
        result = svc.probe(provider_id="stepfun", profile_kind="scanner")
        assert result["status"] == "failed"
        assert result["error_kind"] == "http_error"

    def test_not_configured_maps_to_failed(self, tmp_path, monkeypatch):
        monkeypatch.delenv("STEPFUN_API_KEY")
        monkeypatch.setenv("CODEX_CONFIG_PATH", str(tmp_path / "missing.toml"))
        storage = Storage(tmp_path / "p.db")
        svc = service(storage, lambda request: chat_completions_ok())
        result = svc.probe(provider_id="stepfun", profile_kind="scanner")
        assert result["status"] == "failed"
        assert result["error_kind"] == "not_configured"

    def test_probe_result_survives_restart(self, tmp_path):
        db = tmp_path / "p.db"
        service(Storage(db), lambda request: chat_completions_ok()).probe(
            provider_id="stepfun", profile_kind="scanner")
        assert service(Storage(db), lambda request: chat_completions_ok()).status_for(
            "stepfun", "scanner") == "passed"


class TestCandidateRoutingGate:
    def test_primary_routable_without_probe(self):
        provider = routing_decision()
        assert provider["id"] == "stepfun"
        assert provider["routable"] is True
        env = scanner_provider_environment()
        assert env["LLM_BASE_URL"] == "https://api.stepfun.com/v1"
        assert env["LLM_MODEL"] == "step-5-preview"

    def test_primary_with_failed_probe_is_not_routable(self, tmp_path):
        """Probe 失败的 provider 不进入默认路由，主用也不例外。"""
        storage = Storage(tmp_path / "p.db")
        svc = service(storage, lambda request: httpx.Response(402, json={"error": "quota"}))
        assert svc.probe(provider_id="stepfun", profile_kind="scanner")["status"] == "failed"

        status = svc.probe_status_map()
        stepfun = next(p for p in provider_catalog(status)["providers"] if p["id"] == "stepfun")
        assert stepfun["routable"] is False
        with pytest.raises(ValueError, match="未通过"):
            scanner_provider_environment(status)

    def test_candidate_not_routable_before_probe(self, monkeypatch):
        monkeypatch.setenv("ASGP_MODEL_PROVIDER", "xunfei")
        provider = next(p for p in provider_catalog()["providers"] if p["id"] == "xunfei")
        assert provider["routable"] is False
        with pytest.raises(ValueError, match="未通过"):
            scanner_provider_environment()

    def test_candidate_routable_only_after_passing_probe(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ASGP_MODEL_PROVIDER", "xunfei")
        storage = Storage(tmp_path / "p.db")

        def handler(request: httpx.Request) -> httpx.Response:
            return chat_completions_ok(model="spark-4.0")

        svc = service(storage, handler)
        assert svc.probe(provider_id="xunfei", profile_kind="scanner")["status"] == "passed"

        status = svc.probe_status_map()
        assert routing_decision(status)["routable"] is True
        env = scanner_provider_environment(status)
        assert env["LLM_MODEL"] == "spark-4.0"
        assert env["LLM_BASE_URL"] == "https://maas-api.cn-huabei-1.xf-yun.com/v1"

    def test_failed_probe_blocks_candidate_routing(self, tmp_path, monkeypatch):
        monkeypatch.setenv("ASGP_MODEL_PROVIDER", "xunfei")
        storage = Storage(tmp_path / "p.db")
        svc = service(storage, lambda request: httpx.Response(401, json={"error": "nope"}))
        assert svc.probe(provider_id="xunfei", profile_kind="scanner")["status"] == "failed"

        status = svc.probe_status_map()
        xunfei = next(p for p in provider_catalog(status)["providers"] if p["id"] == "xunfei")
        assert xunfei["routable"] is False
        with pytest.raises(ValueError, match="未通过"):
            scanner_provider_environment(status)

    def test_gate_does_not_silently_fall_back_to_primary(self, tmp_path, monkeypatch):
        """拒绝路由而不是回落到主用，否则配置错误被藏起来。"""
        monkeypatch.setenv("ASGP_MODEL_PROVIDER", "xunfei")
        storage = Storage(tmp_path / "p.db")
        svc = service(storage, lambda request: httpx.Response(500, json={}))
        svc.probe(provider_id="xunfei", profile_kind="scanner")
        status = svc.probe_status_map()
        with pytest.raises(ValueError, match="xunfei"):
            scanner_provider_environment(status)

    def test_catalog_exposes_probe_status_and_routability(self, tmp_path):
        storage = Storage(tmp_path / "p.db")
        svc = service(storage, lambda request: chat_completions_ok())
        svc.probe(provider_id="stepfun", profile_kind="scanner")
        catalog = provider_catalog(svc.probe_status_map())

        stepfun = next(p for p in catalog["providers"] if p["id"] == "stepfun")
        xunfei = next(p for p in catalog["providers"] if p["id"] == "xunfei")
        assert stepfun["probe"]["scanner"] == "passed"
        assert stepfun["probe"]["codex"] == "unknown"
        assert stepfun["routable"] is True
        assert xunfei["probe"]["scanner"] == "unknown"
        assert xunfei["routable"] is False

    def test_unknown_provider_is_rejected(self, monkeypatch):
        monkeypatch.setenv("ASGP_MODEL_PROVIDER", "nobody")
        with pytest.raises(ValueError, match="未知模型供应商"):
            routing_decision({"nobody": "passed"})

    def test_probe_status_accepts_both_mapping_and_callable(self, tmp_path):
        """适配器传查询函数，控制面传映射；两种都要认。"""
        storage = Storage(tmp_path / "p.db")
        svc = service(storage, lambda request: chat_completions_ok())
        svc.probe(provider_id="stepfun", profile_kind="scanner")

        from_mapping = provider_catalog(svc.probe_status_map())
        from_callable = provider_catalog(svc.status_for)
        stepfun_map = next(p for p in from_mapping["providers"] if p["id"] == "stepfun")
        stepfun_call = next(p for p in from_callable["providers"] if p["id"] == "stepfun")
        assert stepfun_map["probe"] == stepfun_call["probe"]
        assert stepfun_map["probe"]["scanner"] == "passed"
        assert routing_decision(svc.status_for)["id"] == "stepfun"


class TestDomainContract:
    def test_candidate_selected_without_probe_is_rejected(self):
        with pytest.raises(ValueError, match="Probe"):
            ModelProviderProfile(
                provider_id="xunfei", name="讯飞星火", role=ProviderRole.CANDIDATE,
                selected=True, probe_status=ProbeStatus.UNKNOWN,
                scanner_profile=WireProfile(wire_api=WireApi.CHAT_COMPLETIONS, source="test"),
            )

    def test_candidate_selected_after_probe_is_allowed(self):
        profile = ModelProviderProfile(
            provider_id="xunfei", name="讯飞星火", role=ProviderRole.CANDIDATE,
            selected=True, probe_status=ProbeStatus.PASSED,
            scanner_profile=WireProfile(wire_api=WireApi.CHAT_COMPLETIONS, source="test"),
        )
        assert profile.selected is True

    def test_primary_selected_without_probe_is_allowed(self):
        profile = ModelProviderProfile(
            provider_id="stepfun", name="StepFun", role=ProviderRole.PRIMARY,
            selected=True, probe_status=ProbeStatus.UNKNOWN,
            scanner_profile=WireProfile(wire_api=WireApi.CHAT_COMPLETIONS, source="test"),
            codex_profile=WireProfile(wire_api=WireApi.RESPONSES, source="codex_config"),
        )
        assert profile.selected is True
