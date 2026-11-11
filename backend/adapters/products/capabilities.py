"""产品 Hook 能力矩阵。

能力是"某产品版本的 hook 协议支持什么"的静态声明，随适配器代码发布而
变化，因此存为代码常量而非数据表（与 DetectorDescriptor 由
Adapter.descriptor() 返回同模式）。矩阵可观测：AgentProductDescriptor
是导出契约，`GET /api/v1/products` 原样回传，前端直接渲染。

当前两个产品都是 UNVERIFIED：Claude Code 的映射来自官方文档，Codex 的
协议形态本身未知。协议尖峰把前者变成实测证据后，对应条目才升级为
VERIFIED 并带上 evidence_ref；在那之前只声明 observe。
"""

from __future__ import annotations

from domain import (
    AgentProductDescriptor,
    CapabilityVerification,
    HookCapability,
    HookEventCapability,
    HookEventType,
    HookTransport,
)
from domain.product import DECISION_NONE

ADAPTER_VERSION = "1.0.0"

# Claude Code payload 里已知但不外传的字段：transcript_path 指向本地会话
# 记录（可能含 prompt 正文），cwd 与 permission_mode 是本机执行上下文。
# 适配器校验它们的存在与类型，但不写进 HookEvent。
CLAUDE_CODE_LOCAL_ONLY_FIELDS = ("transcript_path", "cwd", "permission_mode")


def verified_events(product, version):
    return [HookEventCapability(
        hook_event_type=event_type,
        pre_execution=event_type is HookEventType.PRE_TOOL_USE,
        capabilities=([HookCapability.OBSERVE, HookCapability.CONFIRM, HookCapability.DENY]
            if event_type is HookEventType.PRE_TOOL_USE and product == "claude-code"
            else [HookCapability.OBSERVE, HookCapability.DENY]
            if event_type is HookEventType.PRE_TOOL_USE else [HookCapability.OBSERVE]),
        decision_protocol="stdout_permission_decision" if event_type is HookEventType.PRE_TOOL_USE else DECISION_NONE,
        verification=CapabilityVerification.VERIFIED,
        verified_against=f"{product} {version}; remote test host; StepFun",
        evidence_ref=f"tests/fixtures/hooks/{product}/{version}/{name}.json",
        notes=("已实测放行/阻断；Codex ask 被产品忽略，不支持 confirm。"
            if product == "codex" else "已实测放行/阻断；ask 触发产品确认，同意/拒绝均验证。"),
    ) for name,event_type in [
        ("SessionStart",HookEventType.SESSION_START),
        ("PreToolUse",HookEventType.PRE_TOOL_USE),
        ("PostToolUse",HookEventType.POST_TOOL_USE),
        ("SessionEnd",HookEventType.SESSION_END),
    ]]


def descriptor(product, version, vendor):
    return AgentProductDescriptor(
        product_id=product, product_version=version, adapter_version="1.1.0",
        vendor=vendor, hook_transport=HookTransport.STDIN_JSON,
        collector_id=product+"-hook-v1", events=verified_events(product,version),
        unsupported_fields=list(CLAUDE_CODE_LOCAL_ONLY_FIELDS), ingest_supported=True,
        mediated_approval_supported=True,
        mediated_approval_protocol="asgp_call_digest_approval_then_allow_deny",
        boundary=("原生 Hook ask 不支持；已验证 ASGP 控制面调用审批，批准后 allow，拒绝/超时 deny。"
            if product == "codex" else "已验证原生确认及 ASGP 控制面调用审批；其他版本不继承验证等级。"),
    )


PRODUCT_CAPABILITIES = {
    "claude-code":descriptor("claude-code","2.1.152","Anthropic"),
    "codex":descriptor("codex","0.166.0","OpenAI"),
}
