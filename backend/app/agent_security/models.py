from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SecurityAction(str, Enum):
    ALLOW = "allow"
    ASK = "ask"
    BLOCK = "block"
    AUDIT = "audit"
    ALERT = "alert"


class EventSource(str, Enum):
    SCANNER = "scanner"
    HOOK = "hook"
    MONITOR = "monitor"
    PLATFORM = "platform"


class EventType(str, Enum):
    TOOL_CALL = "tool_call"
    FILE_ACCESS = "file_access"
    NET_CONNECT = "net_connect"
    PROCESS_EXEC = "process_exec"
    CONFIG_CHANGE = "config_change"
    SCAN_FINDING = "scan_finding"
    HEARTBEAT = "heartbeat"


class AssetKind(str, Enum):
    AGENT = "agent"
    MCP = "mcp"
    SKILL = "skill"
    DEPS = "deps"
    HOOK = "hook"


class AssetCarrier(str, Enum):
    MARKETPLACE_CACHE = "marketplace_cache"
    PRODUCT_BUILTIN = "product_builtin"
    USER_INSTALLED = "user_installed"
    PROJECT_LOCAL = "project_local"
    VENDOR_DEPENDENCY = "vendor_dependency"
    SYNTHETIC = "synthetic"
    UNKNOWN = "unknown"


class AssetState(str, Enum):
    DISCOVERED = "discovered"
    CACHED = "cached"
    INSTALLED = "installed"
    ENABLED = "enabled"
    ACTIVE = "active"
    DISABLED = "disabled"
    REMOVED = "removed"


class InstallationState(str, Enum):
    CACHED = "cached"
    INSTALLED = "installed"
    REMOVED = "removed"


class ActivationState(str, Enum):
    ENABLED = "enabled"
    DISABLED = "disabled"


class RuntimeState(str, Enum):
    IDLE = "idle"
    ACTIVE = "active"
    TERMINATED = "terminated"


class ScanVerdict(str, Enum):
    CLEAN = "clean"
    ALERT = "alert"
    BLOCK = "block"


class RiskAssessment(str, Enum):
    UNASSESSED = "unassessed"
    NO_FINDINGS = "no_findings"
    SUSPICIOUS = "suspicious"
    HIGH_RISK_CANDIDATE = "high_risk_candidate"
    CONFIRMED_MALICIOUS = "confirmed_malicious"
    FALSE_POSITIVE = "false_positive"


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AssetRecord(BaseModel):
    asset_id: str
    kind: AssetKind
    name: str
    version: str = ""
    path: str = ""
    sha256: str = ""
    host: str = ""
    owner: str = ""
    source: str = ""
    provenance: str = "unknown"
    risk_assessment: RiskAssessment = RiskAssessment.UNASSESSED
    risk_score: float = 0.0
    ranking_score: float = 0.0
    risk_breakdown: list[dict[str, Any]] = Field(default_factory=list)
    finding_rule_ids: list[str] = Field(default_factory=list)
    assessment_reviewer: str = ""
    assessment_reason: str = ""
    assessment_reviewed_at: str = ""
    ti_provider: str = ""
    ti_verdict: str = "unknown"
    ti_confidence: float = 0.0
    product: str = ""
    publisher: str = "unknown"
    namespace: str = "unknown"
    release_id: str = ""
    signature: str = ""
    source_uri: str = ""
    unknown_reason: str = ""
    execution_origin: dict[str, Any] = Field(default_factory=dict)
    logical_id: str = ""
    instance_id: str = ""
    content_hash: str = ""
    carrier: AssetCarrier = AssetCarrier.UNKNOWN
    state: AssetState = AssetState.DISCOVERED
    installation_state: InstallationState = InstallationState.CACHED
    activation_state: ActivationState = ActivationState.DISABLED
    runtime_state: RuntimeState = RuntimeState.IDLE
    scope: str = "host"
    last_used_at: str = ""
    removed_at: str = ""
    registered: bool = False
    first_seen: str = ""
    last_seen: str = ""


class DeviceEnrollmentRequest(BaseModel):
    device_id: str = Field(min_length=1, max_length=80, pattern=r"^[A-Za-z0-9._-]+$")
    hostname: str = Field(min_length=1, max_length=253)
    owner: str = Field(default="", max_length=120)
    host_role: str = Field(default="test", max_length=80)
    platform: str = Field(default="", max_length=120)


class DeviceEnrollmentResponse(BaseModel):
    device_id: str
    device_token: str
    created_at: str


class DeviceRecord(BaseModel):
    device_id: str
    hostname: str
    owner: str = ""
    host_role: str = ""
    platform: str = ""
    created_at: str = ""
    last_seen: str = ""
    revoked_at: str = ""


class ScanFinding(BaseModel):
    rule_id: str
    name: str
    severity: Severity
    action: SecurityAction
    file: str = ""
    line: int = 0
    evidence: str = ""
    decoded: bool = False


class ScanReport(BaseModel):
    scan_id: str
    ts: str
    host: str
    target_kind: AssetKind
    target_name: str
    target_path: str
    sha256: str
    findings: list[ScanFinding] = Field(default_factory=list)
    verdict: ScanVerdict = ScanVerdict.CLEAN
    registered: bool = False
    drift: bool = False
    risk_assessment: RiskAssessment = RiskAssessment.UNASSESSED
    assessment_reason: str = ""
    risk_score: float = 0.0
    ranking_score: float = 0.0
    risk_breakdown: list[dict[str, Any]] = Field(default_factory=list)
    ti_provider: str = ""
    ti_verdict: str = "unknown"
    ti_confidence: float = 0.0
    ti_iocs: list[dict[str, Any]] = Field(default_factory=list)
    product: str = ""
    logical_id: str = ""
    instance_id: str = ""
    content_hash: str = ""
    carrier: AssetCarrier = AssetCarrier.UNKNOWN
    state: AssetState = AssetState.DISCOVERED
    scope: str = "host"
    inventory_only: bool = False


class AssetInventoryBatch(BaseModel):
    assets: list[AssetRecord] = Field(default_factory=list, max_length=1000)
    scans: list[ScanReport] = Field(default_factory=list, max_length=100)


class AssetRelease(BaseModel):
    release_id: str
    logical_id: str
    version: str = ""
    publisher: str = "unknown"
    namespace: str = "unknown"
    content_hash: str
    signature: str = ""
    source_uri: str = ""
    released_at: str = ""
    revoked_at: str = ""
    resolution_status: str = "resolved"


class AssetDependency(BaseModel):
    parent_instance_id: str
    dependency_type: str
    package_name: str
    requested_version: str = ""
    resolved_version: str = ""
    resolved_hash: str = ""
    source_uri: str = ""
    resolution_status: str = "unknown"


class AdmissionApproval(BaseModel):
    approval_id: str
    decision_id: str
    reviewer: str
    action: str
    scope: str = "host"
    reason: str = ""
    created_at: str = ""
    expires_at: str = ""


class RuntimeEnforcement(BaseModel):
    enforcement_id: str
    event_id: str
    requested_action: SecurityAction
    actual_action: SecurityAction
    product_ack: bool = False
    exit_code: int | None = None
    enforcement_result: str = "unknown"
    adapter_version: str = ""
    ts: str = ""


class AssetAssessmentReview(BaseModel):
    risk_assessment: RiskAssessment
    reviewer: str = Field(min_length=1, max_length=120)
    reason: str = Field(min_length=1, max_length=2000)


class SecurityEvent(BaseModel):
    event_id: str
    ts: str
    source: EventSource
    event_type: EventType
    host: str = ""
    host_role: str = ""
    session_id: str = ""
    agent_name: str = ""
    agent_pid: int | None = None
    tool_name: str = ""
    tool_server: str = ""
    target_kind: str = ""
    target_path: str = ""
    dst_domain: str = ""
    dst_port: int | None = None
    action: SecurityAction = SecurityAction.AUDIT
    rule_ids: list[str] = Field(default_factory=list)
    severity: Severity = Severity.INFO
    ti_verdict: str = "unknown"
    ti_provider: str = ""
    ti_confidence: float = 0.0
    evidence: dict[str, Any] = Field(default_factory=dict)


class EventBatch(BaseModel):
    events: list[SecurityEvent]


class EventIngestResponse(BaseModel):
    accepted: int = 0
    rejected: list[dict[str, str]] = Field(default_factory=list)


class Decision(BaseModel):
    action: SecurityAction
    rule_ids: list[str] = Field(default_factory=list)
    matched_signals: list[str] = Field(default_factory=list)
    reason: str = ""


class TIVerdict(BaseModel):
    provider: str = "threatbook"
    verdict: str = "unknown"
    confidence: float = 0.0
    cached: bool = False


class PolicyRule(BaseModel):
    policy_id: str
    name: str
    kind: str
    pattern: str
    severity: Severity
    action: SecurityAction
    enabled: bool = True
    updated_at: str = ""
    note: str = ""
