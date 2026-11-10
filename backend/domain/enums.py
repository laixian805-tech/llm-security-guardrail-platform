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


class AttributionMethod(StrEnum):
    HOOK_ID = "hook_id"
    PROCESS_TREE = "process_tree"
    TEMPORAL_FEATURE = "temporal_feature"
