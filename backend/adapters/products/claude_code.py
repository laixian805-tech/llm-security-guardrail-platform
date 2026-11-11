"""Claude Code Hook 适配器。

协议来源：Claude Code 官方 Hook 文档，逐条记录在
docs/hook-protocols/claude-code.md。本适配器只做协议映射，不执行阻断
策略；是否出具决策由端侧 fail_mode 决定。

决策通道：三种决策统一走 stdout 的
`hookSpecificOutput.permissionDecision`，永不使用 exit 2。exit 2 的语义
是"阻断并把 stderr 回喂给模型"——observe 模式下误触就是一次未声明的拦
截，且 stderr 不是机器可判定的通道。

字段纪律：payload 里的未知字段一律报错。产品升级加了新字段时，静默忽略
意味着新遥测被无声丢弃；明确失败才能让端侧记录并在下一次协议核对时补上。
"""

from __future__ import annotations

import json
from typing import Any, Mapping

from adapters.products.base import (
    OBSERVE_RESPONSE,
    AgentProductAdapter,
    HookDirective,
    HookEvent,
    HookResponse,
)
from adapters.products.capabilities import (
    CLAUDE_CODE_LOCAL_ONLY_FIELDS,
    PRODUCT_CAPABILITIES,
)
from domain import AgentProductDescriptor, HookEventType, IntentDecision

# 产品事件名 → 中性事件类型。
EVENT_NAMES: dict[str, HookEventType] = {
    "SessionStart": HookEventType.SESSION_START,
    "PreToolUse": HookEventType.PRE_TOOL_USE,
    "PostToolUse": HookEventType.POST_TOOL_USE,
    "SessionEnd": HookEventType.SESSION_END,
}

_COMMON_FIELDS = ("session_id", "transcript_path", "cwd", "permission_mode",
                  "hook_event_name", "model", "effort", "agent_id", "agent_type")
_TOOL_FIELDS = _COMMON_FIELDS + ("tool_name", "tool_input", "tool_use_id", "turn_id")
_EVENT_FIELDS: dict[HookEventType, tuple[str, ...]] = {
    HookEventType.SESSION_START: _COMMON_FIELDS + ("source",),
    HookEventType.PRE_TOOL_USE: _TOOL_FIELDS,
    HookEventType.POST_TOOL_USE: _TOOL_FIELDS + ("tool_response", "duration_ms"),
    HookEventType.SESSION_END: _COMMON_FIELDS + ("reason",),
}

# Claude Code 的 permissionDecision 取值与 IntentDecision 同名同义。
_PERMISSION_DECISIONS = {
    IntentDecision.ALLOW: "allow",
    IntentDecision.ASK: "ask",
    IntentDecision.DENY: "deny",
}


class ClaudeCodeAdapter(AgentProductAdapter):
    """claude-code 的 hook 协议映射。"""

    def descriptor(self) -> AgentProductDescriptor:
        return PRODUCT_CAPABILITIES["claude-code"]

    def parse_hook_input(self, payload: Mapping[str, Any]) -> HookEvent:
        if not isinstance(payload, Mapping):
            raise ValueError("hook 输入必须是 JSON 对象")
        name = payload.get("hook_event_name")
        if not isinstance(name, str) or name not in EVENT_NAMES:
            raise ValueError(f"未知的 hook_event_name：{name!r}")
        event_type = EVENT_NAMES[name]

        known = _EVENT_FIELDS[event_type]
        unknown = sorted(set(payload) - set(known))
        if unknown:
            raise ValueError(
                f"{name} 出现未声明的字段 {unknown}：协议已变化，需核对后补充适配器"
            )

        session_id = _required_str(payload, "session_id")
        # 本地定位字段只做类型校验，不进入中性事件。
        for local_field in CLAUDE_CODE_LOCAL_ONLY_FIELDS:
            if local_field in payload and not isinstance(payload[local_field], str):
                raise ValueError(f"{local_field} 必须是字符串")

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
                result = payload.get("tool_response")
                product_result = result if isinstance(result, str) else _compact(result)
        else:
            tool_name = None
            params = {}
            tool_call_id = None
            product_result = None

        return HookEvent(
            event=name,
            hook_event_type=event_type,
            session_id=session_id,
            # 产品不提供事件时间，occurred_at 由端侧 stamp 接收时间。
            occurred_at=None,
            tool_name=tool_name,
            tool_call_id=tool_call_id,
            params=params,
            product_result=product_result,
        )

    def _render_decision(self, event: HookEvent, directive: HookDirective) -> HookResponse:
        decision = _PERMISSION_DECISIONS.get(directive.decision)
        if decision is None:
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
        return CLAUDE_CODE_LOCAL_ONLY_FIELDS


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
