"""Provider Probe：连通性与能力验收。

Probe 只回答"这条传输 profile 现在能不能用、协议对不对、模型是不是那个、
声明的结构化/工具调用能力有没有被拒绝"，返回成功/延迟/协议/能力，不回传
密钥。Codex 的 Responses profile 和扫描器的 Chat Completions profile 分别
Probe——通过一条不代表另一条可用。

candidate 必须在 Probe 通过后才进入默认路由，所以结果要落库：只在内存里
记的话，重启就把"未通过"忘了。
"""

from __future__ import annotations

import json
import time
from typing import Any

import httpx

from domain import ProbeStatus
from model_providers import resolve_wire_profile
from storage.repositories import ProviderProbeRepository, Storage

PROBE_CONTENT = "ping"

_PROBE_TOOL_CHAT = {
    "type": "function",
    "function": {
        "name": "probe_ping",
        "description": "ASGP connectivity probe",
        "parameters": {"type": "object", "properties": {}},
    },
}

# Responses API 用扁平 schema：name/description/parameters 直接挂在工具上，
# 不是 Chat Completions 的 function 嵌套形式。两者混用会被端点拒绝。
_PROBE_TOOL_RESPONSES = {
    "type": "function",
    "name": "probe_ping",
    "description": "ASGP connectivity probe",
    "parameters": {"type": "object", "properties": {}},
}

# Probe 声明的能力；通过只说明端点接受了这些参数，不说明业务调用一定成功。
PROBE_CAPABILITIES = ("structured_output", "tool_calling")

DEFAULT_TIMEOUT_SECONDS = 20.0


def normalize_wire_api(value: str) -> str:
    """把上游各种写法归一到 WireApi 的取值。"""
    text = (value or "").strip().lower().replace("-", "_").replace(".", "_")
    if text in ("responses",):
        return "responses"
    if text in ("chat_completions", "chatcompletions", "completions"):
        return "chat_completions"
    return text


def _payload(model: str, wire_api: str) -> dict[str, Any]:
    if wire_api == "responses":
        return {
            "model": model,
            "input": PROBE_CONTENT,
            "max_output_tokens": 1,
            "text": {"format": {"type": "json_object"}},
            "tools": [_PROBE_TOOL_RESPONSES],
        }
    return {
        "model": model,
        "messages": [{"role": "user", "content": PROBE_CONTENT}],
        "max_tokens": 1,
        "response_format": {"type": "json_object"},
        "tools": [_PROBE_TOOL_CHAT],
    }


def _endpoint(base_url: str, wire_api: str) -> str:
    return f"{base_url.rstrip('/')}/{wire_api if wire_api == 'responses' else 'chat/completions'}"


def _redact(text: str, secret: str) -> str:
    """把密钥从错误文本里抹掉。错误可能来自上游回显，不能假设它干净。"""
    if not secret:
        return text
    return text.replace(secret, "***")


class ProviderProbeService:
    def __init__(self, *, storage: Storage,
                 timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
                 transport: httpx.BaseTransport | None = None) -> None:
        self._probes = ProviderProbeRepository(storage)
        self._timeout = timeout_seconds
        self._transport = transport

    def probe_status_map(self) -> dict[tuple[str, str], str]:
        return {
            (row["provider_id"], row["profile_kind"]): row["status"]
            for row in self._probes.latest_all()
        }

    def status_for(self, provider_id: str, profile_kind: str) -> str:
        row = self._probes.latest(provider_id, profile_kind)
        return row["status"] if row else ProbeStatus.UNKNOWN.value

    def probe(self, *, provider_id: str, profile_kind: str) -> dict[str, Any]:
        profile = resolve_wire_profile(provider_id, profile_kind)
        wire_api = normalize_wire_api(profile["wire_api"])

        if not profile["configured"] or wire_api not in ("responses", "chat_completions"):
            return self._record(
                provider_id=provider_id, profile_kind=profile_kind, profile=profile,
                wire_api=wire_api, status=ProbeStatus.FAILED, latency_ms=None,
                http_status=None, error_kind="not_configured",
                error=profile["missing_hint"] if not profile["configured"]
                else f"无法识别 wire_api：{profile['wire_api']!r}",
                capabilities=[], model_echoed="",
            )

        url = _endpoint(profile["base_url"], wire_api)
        headers = {
            "Authorization": f"Bearer {profile['api_key']}",
            "Content-Type": "application/json",
        }
        body = _payload(profile["model"], wire_api)

        started = time.monotonic()
        try:
            with httpx.Client(timeout=self._timeout, transport=self._transport) as client:
                response = client.post(url, json=body, headers=headers)
        except httpx.TimeoutException:
            return self._record(
                provider_id=provider_id, profile_kind=profile_kind, profile=profile,
                wire_api=wire_api, status=ProbeStatus.FAILED, latency_ms=None,
                http_status=None, error_kind="timeout",
                error=f"Probe 超过 {self._timeout:g} 秒未响应。",
                capabilities=[], model_echoed="",
            )
        except httpx.HTTPError as exc:
            return self._record(
                provider_id=provider_id, profile_kind=profile_kind, profile=profile,
                wire_api=wire_api, status=ProbeStatus.FAILED, latency_ms=None,
                http_status=None, error_kind="unreachable",
                error=_redact(f"无法连接 {url}：{exc}", profile["api_key"]),
                capabilities=[], model_echoed="",
            )

        # 自己计时：MockTransport 构造的 Response 没有 elapsed，真实传输才有。
        latency_ms = int((time.monotonic() - started) * 1000)
        http_status = response.status_code
        try:
            document = response.json()
        except ValueError:
            document = {}

        if http_status in (401, 403):
            return self._record(
                provider_id=provider_id, profile_kind=profile_kind, profile=profile,
                wire_api=wire_api, status=ProbeStatus.FAILED, latency_ms=latency_ms,
                http_status=http_status, error_kind="unauthorized",
                error=_redact(f"端点返回 {http_status}，凭据不被接受。", profile["api_key"]),
                capabilities=[], model_echoed="",
            )
        if http_status == 400:
            detail = _error_text(document) or response.text[:500]
            if _rejects_capability(detail):
                return self._record(
                    provider_id=provider_id, profile_kind=profile_kind, profile=profile,
                    wire_api=wire_api, status=ProbeStatus.FAILED, latency_ms=latency_ms,
                    http_status=http_status, error_kind="capability_rejected",
                    error=_redact(f"端点拒绝 Probe 声明的能力：{detail}", profile["api_key"]),
                    capabilities=[], model_echoed="",
                )
        if not 200 <= http_status < 300:
            return self._record(
                provider_id=provider_id, profile_kind=profile_kind, profile=profile,
                wire_api=wire_api, status=ProbeStatus.FAILED, latency_ms=latency_ms,
                http_status=http_status, error_kind="http_error",
                error=_redact(f"端点返回 {http_status}：{_error_text(document) or response.text[:500]}",
                              profile["api_key"]),
                capabilities=[], model_echoed="",
            )

        model_echoed = str(document.get("model") or "")
        if not _shape_ok(document, wire_api):
            return self._record(
                provider_id=provider_id, profile_kind=profile_kind, profile=profile,
                wire_api=wire_api, status=ProbeStatus.FAILED, latency_ms=latency_ms,
                http_status=http_status, error_kind="protocol_mismatch",
                error=f"响应形状不像 {wire_api}：缺少预期字段。",
                capabilities=[], model_echoed=model_echoed,
            )
        if not model_echoed:
            return self._record(
                provider_id=provider_id, profile_kind=profile_kind, profile=profile,
                wire_api=wire_api, status=ProbeStatus.FAILED, latency_ms=latency_ms,
                http_status=http_status, error_kind="protocol_mismatch",
                error=f"{wire_api} 响应缺少 model 字段，无法确认模型身份。",
                capabilities=[], model_echoed="",
            )
        # Codex 的 model 由客户端决定，profile 里没有声明，无法核对身份；
        # 这时只记录端点返回的模型，不断言失败。
        expected_model = profile["model"].strip()
        if expected_model and model_echoed.strip().lower() != expected_model.lower():
            return self._record(
                provider_id=provider_id, profile_kind=profile_kind, profile=profile,
                wire_api=wire_api, status=ProbeStatus.FAILED, latency_ms=latency_ms,
                http_status=http_status, error_kind="model_mismatch",
                error=f"请求模型 {expected_model}，端点返回 {model_echoed}。",
                capabilities=[], model_echoed=model_echoed,
            )

        return self._record(
            provider_id=provider_id, profile_kind=profile_kind, profile=profile,
            wire_api=wire_api, status=ProbeStatus.PASSED, latency_ms=latency_ms,
            http_status=http_status, error_kind=None, error=None,
            capabilities=list(PROBE_CAPABILITIES), model_echoed=model_echoed,
        )

    def _record(self, *, provider_id: str, profile_kind: str, profile: dict[str, Any],
                wire_api: str, status: ProbeStatus, latency_ms: int | None,
                http_status: int | None, error_kind: str | None, error: str | None,
                capabilities: list[str], model_echoed: str) -> dict[str, Any]:
        self._probes.record(
            provider_id=provider_id, profile_kind=profile_kind, wire_api=wire_api,
            base_url=profile["base_url"], model=profile["model"], status=status.value,
            latency_ms=latency_ms, http_status=http_status, error_kind=error_kind,
            error=error, capabilities=capabilities,
        )
        return {
            "provider_id": provider_id,
            "profile_kind": profile_kind,
            "wire_api": wire_api,
            "base_url": profile["base_url"],
            "model": profile["model"],
            "model_echoed": model_echoed,
            "status": status.value,
            "latency_ms": latency_ms,
            "http_status": http_status,
            "capabilities": capabilities,
            "error_kind": error_kind,
            "error": error,
        }


def _error_text(document: Any) -> str:
    if not isinstance(document, dict):
        return ""
    error = document.get("error")
    if isinstance(error, dict):
        message = error.get("message") or error.get("code") or ""
        return str(message)[:500]
    if isinstance(error, str):
        return error[:500]
    return str(document.get("message") or "")[:500]


def _rejects_capability(detail: str) -> bool:
    text = detail.lower()
    markers = ("response_format", "tools", "tool", "json_object", "unsupported", "not support",
               "invalid_parameter", "parameter")
    return any(marker in text for marker in markers)


def _shape_ok(document: dict[str, Any], wire_api: str) -> bool:
    if not isinstance(document, dict):
        return False
    if wire_api == "responses":
        return bool(document.get("id")) and isinstance(document.get("output"), list)
    choices = document.get("choices")
    return isinstance(choices, list) and bool(choices)
