"""Agent 产品 Hook 能力契约。

产品适配器把各产品的 hook 协议映射成中性事件；本契约是那份映射的静态
声明，供控制台与端点查询"这个产品到底支持什么"。

VERIFIED 与 UNVERIFIED 的分界是这份契约的核心：没有实测证据的条目只
允许 observe、不得声明决策通道。否则 observe 模式下采到的事件会被呈现
成"拦住了"，而这正是 P1 验收 A3 明令禁止的。
"""

from __future__ import annotations

from pydantic import Field, model_validator

from domain.asset import StrictModel
from domain.enums import (
    CapabilityVerification,
    HookCapability,
    HookEventType,
    HookTransport,
)

# 决策通道取值。"none" 表示该事件没有机器可判定的决策回路。
DECISION_NONE = "none"
DECISION_STDOUT_PERMISSION = "stdout_permission_decision"


class HookEventCapability(StrictModel):
    """单个 hook 事件类型的能力条目。"""

    hook_event_type: HookEventType
    # 该事件是否位于工具执行之前：只有执行前事件才谈得上 confirm/deny。
    pre_execution: bool
    capabilities: list[HookCapability] = Field(min_length=1)
    decision_protocol: str = DECISION_NONE
    verification: CapabilityVerification = CapabilityVerification.UNVERIFIED
    # VERIFIED 时必填：对哪个产品版本、用什么方式验证的，证据在哪。
    verified_against: str | None = None
    evidence_ref: str | None = None
    # 给界面直接展示的补充说明。
    notes: str = ""

    @model_validator(mode="after")
    def _check_verification(self) -> HookEventCapability:
        declared = set(self.capabilities)
        blocking = declared & {HookCapability.CONFIRM, HookCapability.DENY}
        if self.verification is CapabilityVerification.UNVERIFIED:
            if blocking:
                raise ValueError(
                    "未实测条目不得声明 confirm/deny：没有证据表明产品会执行该决策"
                )
            if self.decision_protocol != DECISION_NONE:
                raise ValueError("未实测条目不得声明决策通道")
            if self.verified_against or self.evidence_ref:
                raise ValueError("未验证条目不得填写验证来源")
        elif not self.verified_against or not self.evidence_ref:
            raise ValueError("VERIFIED 条目必须记录 verified_against 与 evidence_ref")

        if blocking and not self.pre_execution:
            raise ValueError("只有执行前事件可以声明 confirm/deny")
        if blocking and self.decision_protocol == DECISION_NONE:
            raise ValueError("声明了 confirm/deny 就必须说明决策通道")
        return self


class AgentProductDescriptor(StrictModel):
    """产品 Hook 的静态能力声明，由适配器提供。"""

    product_id: str = Field(min_length=1)
    # 适配器针对的产品版本；能力随产品版本变化，不跨版本继承。
    product_version: str = Field(min_length=1)
    adapter_version: str = Field(min_length=1)
    vendor: str = Field(min_length=1)
    hook_transport: HookTransport = HookTransport.UNKNOWN
    # 采集器标识，写入 RuntimeEvent.collector_id。
    collector_id: str = Field(min_length=1)
    # 每个 hook 事件类型至多一条。
    events: list[HookEventCapability] = Field(default_factory=list)
    # 产品 payload 中本适配器不消费的字段：要么是不外传的本地定位字段，
    # 要么是本产品不提供的字段。
    unsupported_fields: list[str] = Field(default_factory=list)
    # ASGP 是否能实际摄入该产品的 hook 事件。
    ingest_supported: bool = True
    # ingest_supported 为 False 时必填：界面必须展示原因，不能用空数组蒙混。
    unsupported_reason: str = ""
    # 运行边界说明，直接展示给用户。
    boundary: str = ""

    @model_validator(mode="after")
    def _check_ingest(self) -> AgentProductDescriptor:
        if self.ingest_supported:
            if not self.events:
                raise ValueError("可摄入的产品至少声明一个 hook 事件能力")
        else:
            if self.events:
                raise ValueError("无法摄入的产品不得声明事件能力")
            if not self.unsupported_reason:
                raise ValueError("无法摄入必须给出 unsupported_reason")
        seen = [entry.hook_event_type for entry in self.events]
        if len(set(seen)) != len(seen):
            raise ValueError("同一 hook_event_type 不得重复声明能力")
        return self

    def capability_for(self, hook_event_type: HookEventType) -> HookEventCapability | None:
        for entry in self.events:
            if entry.hook_event_type is hook_event_type:
                return entry
        return None

    @property
    def verification(self) -> CapabilityVerification:
        """产品级验证等级，取最保守的条目等级。

        任一事件类型未实测，产品就是未实测：聚合值不允许被最好的一条
        拉高，否则界面会拿一个实测事件给整个产品背书。
        """
        if not self.events:
            return CapabilityVerification.UNVERIFIED
        if any(entry.verification is CapabilityVerification.UNVERIFIED
               for entry in self.events):
            return CapabilityVerification.UNVERIFIED
        return CapabilityVerification.VERIFIED
