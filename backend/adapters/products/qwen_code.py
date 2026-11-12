"""Qwen Code Hook 适配器。

协议来源：qwen-code 0.27.2 实测录制，样本在
``tests/fixtures/hooks/qwen-code/0.27.2/``，实验记录见
``docs/acceptance/2026-11-12-qwen-adapter.md``。

与 Claude Code 的差异（都是实测出来的，不是推测）：

- 多 ``timestamp``：可直接作为事件时间，不必由端侧 stamp 接收时间。
- ``PreToolUse``/``PostToolUse`` 多 ``prompt_id`` 与 ``tool_call_id``。
- ``tool_response`` 是结构化对象（``llmContent``/``returnDisplay``），
  不是字符串。
- ``SessionEnd`` 本轮没有捕获到，因此不声明该事件：没测过的事件不给能力。
- ``ask`` 未实测，只声明 observe/deny。

决策通道与 Claude Code 相同（stdout 的
``hookSpecificOutput.permissionDecision``），deny 已实测为硬阻断：被 deny 的
``run_shell_command`` 没有产生文件系统后果，allow 的产生了，PostToolUse
只对放行的那次触发。
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Mapping

from adapters.products.base import (
    OBSERVE_RESPONSE,
    AgentProductAdapter,
    HookDirective,
    HookEvent,
    HookResponse,
)
from adapters.products.capabilities import (
    PRODUCT_CAPABILITIES,
    QWEN_CODE_LOCAL_ONLY_FIELDS,
)
from domain import AgentProductDescriptor, HookEventType, IntentDecision

EVENT_NAMES: dict[str, HookEventType] = {
    "SessionStart": HookEventType.SESSION_START,
    "PreToolUse": HookEventType.PRE_TOOL_USE,
    "PostToolUse": HookEventType.POST_TOOL_USE,
}

_COMMON_FIELDS = ("session_id", "transcript_path", "cwd", "hook_event_name",
                  "timestamp", "permission_mode")
_TOOL_FIELDS = _COMMON_FIELDS + ("prompt_id", "tool_name", "tool_input",
                                 "tool_use_id", "tool_call_id")
_EVENT_FIELDS: dict[HookEventType, tuple[str, ...]] = {
    HookEventType.SESSION_START: _COMMON_FIELDS + ("source", "model"),
    HookEventType.PRE_TOOL_USE: _TOOL_FIELDS,
    HookEventType.POST_TOOL_USE: _TOOL_FIELDS + ("tool_response", "duration_ms"),
}

_PERMISSION_DECISIONS = {
    IntentDecision.ALLOW: "allow",
    IntentDecision.DENY: "deny",
}


class QwenCodeAdapter(AgentProductAdapter):
    """qwen-code 的 hook 协议映射。"""

    def descriptor(self) -> AgentProductDescriptor:
        return PRODUCT_CAPABILITIES["qwen-code"]

    def parse_hook_input(self, payload: Mapping[str, Any]) -> HookEvent:
        if not isinstance(payload, Mapping):
            raise ValueError("hook 输入必须是 JSON 对象")
        name = payload.get("hook_event_name")
        if not isinstance(name, str) or name not in EVENT_NAMES:
            # SessionEnd 也在这一支：本轮未捕获其 payload，不猜字段。
            raise ValueError(f"未声明或未实测的 hook_event_name：{name!r}")
        event_type = EVENT_NAMES[name]

        unknown = sorted(set(payload) - set(_EVENT_FIELDS[event_type]))
        if unknown:
            raise ValueError(
                f"{name} 出现未声明的字段 {unknown}：协议已变化，需核对后补充适配器"
            )

        session_id = _required_str(payload, "session_id")
        for local_field in QWEN_CODE_LOCAL_ONLY_FIELDS:
            if local_field in payload and not isinstance(payload[local_field], str):
                raise ValueError(f"{local_field} 必须是字符串")

        occurred_at = None
        raw_time = payload.get("timestamp")
        if raw_time is not None:
            if not isinstance(raw_time, str):
                raise ValueError("timestamp 必须是 ISO8601 字符串")
            try:
                occurred_at = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
            except ValueError as exc:
                raise ValueError(f"timestamp 不是合法 ISO8601：{raw_time!r}") from exc

        if event_type in (HookEventType.PRE_TOOL_USE, HookEventType.POST_TOOL_USE):
            tool_name = _required_str(payload, "tool_name")
            params = payload.get("tool_input")
            if not isinstance(params, Mapping):
                raise ValueError(f"{name} 的 tool_input 必须是对象")
            tool_call_id = payload.get("tool_use_id")
            if tool_call_id is not None and not isinstance(tool_call_id, str):
                raise ValueError("tool_use_id 必须是字符串")
            product_result = None
            if event_type is HookEventType.POST_TOOL_USE:
                product_result = _compact(payload.get("tool_response"))
        else:
            tool_name = None
            params = {}
            tool_call_id = None
            product_result = None

        return HookEvent(
            event=name,
            hook_event_type=event_type,
            session_id=session_id,
            occurred_at=occurred_at,
            tool_name=tool_name,
            tool_call_id=tool_call_id,
            params=params,
            product_result=product_result,
        )

    def _render_decision(self, event: HookEvent, directive: HookDirective) -> HookResponse:
        decision = _PERMISSION_DECISIONS.get(directive.decision)
        if decision is None:
            # ask 未实测，不渲染：宁可 observe 也不发一个产品可能忽略的指令。
            return OBSERVE_RESPONSE
        output = {
            "hookSpecificOutput": {
                "hookEventName": event.event,
                "permissionDecision": decision,
            }
        }
        if directive.reason:
            output["hookSpecificOutput"]["permissionDecisionReason"] = directive.reason
        return HookResponse(exit_code=0, stdout=json.dumps(output, ensure_ascii=False))

    def unsupported_fields(self) -> tuple[str, ...]:
        return QWEN_CODE_LOCAL_ONLY_FIELDS


def _required_str(payload: Mapping[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{key} 必须是非空字符串")
    return value


def _compact(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True)
