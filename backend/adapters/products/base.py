"""AgentProductAdapter 统一接口。

产品适配器只做协议转换：把产品的 hook 输入映射成中性 HookEvent，把中性
HookDirective 渲染成产品认识的退出方式。适配器不写库、不触网、不持有
会话状态——hook 进程每次工具调用启动一次，构造必须廉价。

render_directive 对非执行前事件一律返回 observe：这是接口层的硬约束，
不依赖调用方自觉。observe 模式下出具阻断指令就是一次未声明的拦截。
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping

from domain import (
    PRE_EXECUTION_HOOK_EVENTS,
    AgentProductDescriptor,
    HookEventType,
    IntentDecision,
)


class UnsupportedHookProtocol(RuntimeError):
    """产品的 hook 协议未实测，适配器拒绝解析。

    用一个猜出来的字段映射去"支持"一个产品，比明确不支持更危险：解析
    静默出错时，观测数据看起来是全的。
    """


@dataclass(frozen=True)
class HookEvent:
    """产品 hook 输入的中性表示。

    params 与 product_result 是脱敏前的原始值，只活在内存里：离开本对象
    前必须经过端侧脱敏，否则原始 tool_input 就随上报外泄了。
    occurred_at 为 None 表示产品不提供事件时间，由端侧 stamp 接收时间。
    """

    event: str
    hook_event_type: HookEventType
    session_id: str
    occurred_at: datetime | None = None
    tool_name: str | None = None
    tool_call_id: str | None = None
    params: Mapping[str, Any] = field(default_factory=dict)
    product_result: str | None = None

    def neutral(self) -> dict[str, Any]:
        """纯数据视图，供端侧与控制面实现的 drift 守卫比对。

        调用方负责先脱敏：这里包含原始 params。
        """
        return {
            "event": self.event,
            "hook_event_type": self.hook_event_type.value,
            "session_id": self.session_id,
            "occurred_at": self.occurred_at.isoformat() if self.occurred_at else None,
            "tool_name": self.tool_name,
            "tool_call_id": self.tool_call_id,
            "params": dict(self.params),
            "product_result": self.product_result,
        }


@dataclass(frozen=True)
class HookDirective:
    """给产品 hook 的决策指令。"""

    decision: IntentDecision = IntentDecision.NOT_APPLICABLE
    reason: str = ""


@dataclass(frozen=True)
class HookResponse:
    """hook 进程的退出方式。"""

    exit_code: int = 0
    stdout: str = ""


# observe 的规范形态：退出 0、stdout 空。hook 进程不得在观察模式下
# 往 stdout 写任何东西，那会被产品当成指令。
OBSERVE_RESPONSE = HookResponse(exit_code=0, stdout="")


class AgentProductAdapter(ABC):
    """所有产品适配器必须实现的契约。"""

    @abstractmethod
    def descriptor(self) -> AgentProductDescriptor:
        """静态能力声明，含验证等级与边界说明。"""

    def collector_id(self) -> str:
        return self.descriptor().collector_id

    @abstractmethod
    def parse_hook_input(self, payload: Mapping[str, Any]) -> HookEvent:
        """把产品 hook stdin 的 JSON 映射成中性事件。"""

    def render_directive(self, event: HookEvent, directive: HookDirective) -> HookResponse:
        """把中性决策渲染成产品认识的退出方式。

        两道硬闸：非执行前事件、以及没有决策语义的指令，一律 observe。
        """
        if event.hook_event_type not in PRE_EXECUTION_HOOK_EVENTS:
            return OBSERVE_RESPONSE
        if directive.decision is IntentDecision.NOT_APPLICABLE:
            return OBSERVE_RESPONSE
        return self._render_decision(event, directive)

    @abstractmethod
    def _render_decision(self, event: HookEvent, directive: HookDirective) -> HookResponse:
        """执行前事件的决策渲染；非执行前事件不会到达这里。"""

    @abstractmethod
    def unsupported_fields(self) -> tuple[str, ...]:
        """产品 payload 中本适配器不消费的字段。"""
