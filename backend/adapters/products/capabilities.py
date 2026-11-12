"""产品 Hook 能力矩阵。

能力是"某产品版本的 hook 协议支持什么"的静态声明，随适配器代码发布而
变化，因此存为代码常量而非数据表（与 DetectorDescriptor 由
Adapter.descriptor() 返回同模式）。矩阵可观测：AgentProductDescriptor
是导出契约，`GET /api/v1/products` 原样回传，前端直接渲染。

当前三个产品都是 VERIFIED，但验证范围不同：Claude Code 有 observe/confirm/
deny 三档；Codex 没有原生 ask，只声明 observe/deny；qwen-code 0.27.2 实测到
deny 是硬阻断、ask 未测，且 SessionEnd 未捕获，因此只声明三个事件、不含
confirm。每个条目的 evidence_ref 指向录制样本，没有样本的能力不声明。
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

# 适配器版本：descriptor 一律引用这个常量。曾经这里写 "1.0.0"、descriptor 里
# 另写 "1.1.0"，改常量不生效——版本号有常量就必须只有一处真值。
ADAPTER_VERSION = "1.1.0"

# 各产品的验证版本。版本门控要求它与设备上报值相等，所以这里就是"声明版本"
# 的唯一来源；改版本只动这一处。
PRODUCT_VERSIONS = {"claude-code": "2.1.152", "codex": "0.166.0", "qwen-code": "0.26.8"}

# Claude Code payload 里已知但不外传的字段：transcript_path 指向本地会话
# 记录（可能含 prompt 正文），cwd 与 permission_mode 是本机执行上下文。
# 适配器校验它们的存在与类型，但不写进 HookEvent。
CLAUDE_CODE_LOCAL_ONLY_FIELDS = ("transcript_path", "cwd", "permission_mode")

# qwen-code 额外提供 prompt_id：会话内单次提示的标识，属于本机会话结构，
# 不上传。字段集来自 0.27.2 实测录制，不是官方文档推断。
QWEN_CODE_LOCAL_ONLY_FIELDS = ("transcript_path", "cwd", "permission_mode", "prompt_id")

# qwen-code 0.27.2 只实测到三个事件：SessionEnd 本轮没有捕获到 payload，
# 因此不声明它——没测过的事件不给能力。
QWEN_CODE_EVENTS = (
    ("SessionStart", HookEventType.SESSION_START),
    ("PreToolUse", HookEventType.PRE_TOOL_USE),
    ("PostToolUse", HookEventType.POST_TOOL_USE),
)

_DEFAULT_EVENTS = (
    ("SessionStart", HookEventType.SESSION_START),
    ("PreToolUse", HookEventType.PRE_TOOL_USE),
    ("PostToolUse", HookEventType.POST_TOOL_USE),
    ("SessionEnd", HookEventType.SESSION_END),
)


def verified_events(product, version, names=None):
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
        notes=(("已实测放行/阻断；Codex ask 被产品忽略，不支持 confirm。"
            if product == "codex" else
            "已实测放行/阻断；ask 未实测，不声明 confirm。"
            if product == "qwen-code" else
            "已实测放行/阻断；ask 触发产品确认，同意/拒绝均验证。")),
    ) for name,event_type in (names or _DEFAULT_EVENTS)]


def _boundary(product):
    if product == "codex":
        return "原生 Hook ask 不支持；已验证 ASGP 控制面调用审批，批准后 allow，拒绝/超时 deny。"
    if product == "qwen-code":
        return ("deny 经实测为硬阻断（被拒命令无文件系统后果）；ask 未实测，不声明 confirm；"
                "SessionEnd 未捕获，不声明该事件；其他版本不继承验证等级。")
    return "已验证原生确认及 ASGP 控制面调用审批；其他版本不继承验证等级。"


def descriptor(product, version, vendor, events=None, unsupported_fields=None):
    return AgentProductDescriptor(
        product_id=product, product_version=version, adapter_version=ADAPTER_VERSION,
        vendor=vendor, hook_transport=HookTransport.STDIN_JSON,
        collector_id=product+"-hook-v1", events=verified_events(product,version,events),
        unsupported_fields=list(unsupported_fields or CLAUDE_CODE_LOCAL_ONLY_FIELDS),
        ingest_supported=True,
        mediated_approval_supported=True,
        mediated_approval_protocol="asgp_call_digest_approval_then_allow_deny",
        boundary=_boundary(product),
    )


PRODUCT_CAPABILITIES = {
    "claude-code":descriptor("claude-code",PRODUCT_VERSIONS["claude-code"],"Anthropic"),
    "codex":descriptor("codex",PRODUCT_VERSIONS["codex"],"OpenAI"),
    # 声明版本取设备实版本：版本门控要求 descriptor.product_version 与执行上报
    # 的 product_version 相等，声明 0.27.2 会让 0.26.8 的决策记录被拒收。
    # 0.27.2 的抓包协议形状与 0.26.8 一致（同字段集），测试对两个版本都跑。
    "qwen-code":descriptor("qwen-code",PRODUCT_VERSIONS["qwen-code"],"Alibaba",events=QWEN_CODE_EVENTS,
                           unsupported_fields=QWEN_CODE_LOCAL_ONLY_FIELDS),
}
