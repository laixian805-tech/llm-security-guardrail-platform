"""ASGP 领域契约的共享枚举。

severity 与 confidence 必须分开：severity 描述潜在影响，confidence 描述
证据强度。未知严重度用 UNKNOWN，禁止从 risk_score 反推。
"""

from __future__ import annotations

from enum import StrEnum


class AssetType(StrEnum):
    AGENT = "agent"
    SKILL = "skill"
    MCP_SERVER = "mcp_server"
    PLUGIN = "plugin"
    TOOL = "tool"


class Severity(StrEnum):
    UNKNOWN = "unknown"
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class InstallationState(StrEnum):
    UNKNOWN = "unknown"
    ABSENT = "absent"
    INSTALLED = "installed"
    BROKEN = "broken"


class ActivationState(StrEnum):
    UNKNOWN = "unknown"
    DISABLED = "disabled"
    ENABLED = "enabled"


class RuntimeState(StrEnum):
    UNKNOWN = "unknown"
    IDLE = "idle"
    RUNNING = "running"
    STOPPED = "stopped"


class FindingStatus(StrEnum):
    NEW = "new"
    TRIAGED = "triaged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    REOPENED = "reopened"


class DetectorMode(StrEnum):
    STATIC = "static"
    DYNAMIC = "dynamic"


class RunStatus(StrEnum):
    """检测器运行状态。

    SUCCEEDED 且 finding_count 为 0 才表示 clean；TIMED_OUT、
    FAILED、OUTPUT_LIMIT_EXCEEDED 都不得呈现为无发现项。
    """

    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    OUTPUT_LIMIT_EXCEEDED = "output_limit_exceeded"
    CANCELLED = "cancelled"


class WireApi(StrEnum):
    RESPONSES = "responses"
    CHAT_COMPLETIONS = "chat_completions"


class ProviderRole(StrEnum):
    PRIMARY = "primary"
    CANDIDATE = "candidate"


class ProbeStatus(StrEnum):
    UNKNOWN = "unknown"
    PASSED = "passed"
    FAILED = "failed"


class HookCapability(StrEnum):
    OBSERVE = "observe"
    CONFIRM = "confirm"
    DENY = "deny"


class HookTransport(StrEnum):
    """产品 Hook 的输入输出如何送达。

    STDIN_JSON：产品把事件 JSON 写进 hook 进程 stdin，决策经 stdout 返回。
    UNKNOWN：未实测，不知道是否存在 hook 机制以及其形态。
    """

    STDIN_JSON = "stdin_json"
    UNKNOWN = "unknown"


class CapabilityVerification(StrEnum):
    """能力条目的证据等级。

    VERIFIED 必须带 verified_against 与 evidence_ref——没有证据的"支持"
    就是宣称已拦截。UNVERIFIED 只允许 observe 且不得声明决策通道：协议
    没实测就声称能阻断，拦不住时没有任何告警。
    """

    VERIFIED = "verified"
    UNVERIFIED = "unverified"


class HookEventType(StrEnum):
    """产品 Hook 事件类型。

    SYNTHETIC 是端点自己合成的事件（如关联、补录），不是产品真实抛出
    的执行前观测，因此不算执行前事件。
    """

    SESSION_START = "session_start"
    PRE_TOOL_USE = "pre_tool_use"
    POST_TOOL_USE = "post_tool_use"
    SESSION_END = "session_end"
    SYNTHETIC = "synthetic"


# 只有 PreToolUse 是真的位于工具执行之前；SessionStart/End、PostToolUse
# 和合成事件都不得携带阻断或询问决策。
PRE_EXECUTION_HOOK_EVENTS = frozenset({HookEventType.PRE_TOOL_USE})


class IntentDecision(StrEnum):
    """Intent 上观测到的决策。

    NOT_APPLICABLE 表示该事件没有决策语义（observe 模式或非执行前事件），
    与"决策为放行"是两回事。
    """

    NOT_APPLICABLE = "not_applicable"
    ALLOW = "allow"
    ASK = "ask"
    DENY = "deny"


class ExecutionOutcome(StrEnum):
    """一次执行的结果状态。

    RUNNING 表示会话未收尾；UNKNOWN 表示从未观测到收尾事件（端点离线
    等情况），不得当作 completed。
    """

    UNKNOWN = "unknown"
    RUNNING = "running"
    COMPLETED = "completed"
    ABORTED = "aborted"
    FAILED = "failed"


class AttributionMethod(StrEnum):
    HOOK_ID = "hook_id"
    PROCESS_TREE = "process_tree"
    TEMPORAL_FEATURE = "temporal_feature"


class SourceKind(StrEnum):
    """触发工具调用的指令来源类别，用于区分高信任任务指令与外部低信任内容。"""

    USER_TASK = "user_task"
    WORKSPACE_CONFIG = "workspace_config"
    INSTALLED_SKILL = "installed_skill"
    MCP_SERVER = "mcp_server"
    TOOL_OUTPUT = "tool_output"
    UNKNOWN = "unknown"


class EffectDiffVerdict(StrEnum):
    """模型预期副作用边界与 OS 实测事件之间的差分结论。"""

    WITHIN_EXPECTED = "within_expected"
    UNDECLARED_SIDE_EFFECT = "undeclared_side_effect"
    NO_OBSERVED_EFFECT = "no_observed_effect"
    UNVERIFIED = "unverified"


class PolicyAction(StrEnum):
    ALLOW = "allow"
    AUDIT = "audit"
    CONFIRM = "confirm"
    BLOCK = "block"


class AdmissionState(StrEnum):
    CHECK = "check"
    APPROVED = "approved"
    STAGED = "staged"
    COMMITTED = "committed"
    VERIFIED = "verified"
    RECONCILED = "reconciled"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"


class PolicyStatus(StrEnum):
    DRAFT = "draft"
    ACTIVE = "active"
    RETIRED = "retired"


class IncidentStatus(StrEnum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    MITIGATING = "mitigating"
    VERIFYING = "verifying"
    CLOSED = "closed"
    REOPENED = "reopened"


class ConsoleRole(StrEnum):
    """控制台用户角色。设备身份不走这套权限，见 DeviceStatus。"""

    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"


class Permission(StrEnum):
    READ = "read"
    SCAN = "scan"
    PROBE = "probe"
    IMPORT_REPORT = "import_report"
    MANAGE_USERS = "manage_users"
    MANAGE_RETENTION = "manage_retention"
    READ_AUDIT = "read_audit"
    # 原始报告含扫描器整段输出，可能带目标源码片段，不给只读角色。
    READ_RAW_REPORT = "read_raw_report"
    GOVERN = "govern"


class ActorKind(StrEnum):
    """谁发起了这次动作。

    console_user 与 device 必须分开：设备令牌只代表一台端点的上报身份，
    不等于控制台用户的权限。
    """

    CONSOLE_USER = "console_user"
    DEVICE = "device"
    ANONYMOUS = "anonymous"


class AuditOutcome(StrEnum):
    SUCCESS = "success"
    DENIED = "denied"
    ERROR = "error"


class DeviceStatus(StrEnum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    REVOKED = "revoked"


class RetentionKind(StrEnum):
    DETECTOR_RUNS = "detector_runs"
    RAW_REPORTS = "raw_reports"
    AUDIT_EVENTS = "audit_events"
    EXECUTIONS = "executions"
    RUNTIME_EVENTS = "runtime_events"
