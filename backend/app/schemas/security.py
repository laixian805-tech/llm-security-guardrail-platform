from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, computed_field, model_validator


class GuardStage(str, Enum):
    PRE_INPUT = "pre_input"
    PRE_TOOL = "pre_tool"
    POST_OUTPUT = "post_output"


class GuardAction(str, Enum):
    BLOCK = "block"
    AUDIT = "audit"
    ALLOW = "allow"


class ToolTier(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    ADMIN = "admin"


class ToolDecision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    AUDIT = "audit"


class EvalStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class AttackCategory(str, Enum):
    INJECTION = "injection"
    JAILBREAK = "jailbreak"
    ENCODING = "encoding"
    ROLE_OVERRIDE = "role_override"


class GuardResult(BaseModel):
    stage: GuardStage
    rule_name: str
    triggered: bool
    confidence: float = Field(ge=0.0, le=1.0)
    action: GuardAction
    reason: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class SessionGuardStats(BaseModel):
    total_checks: int = 0
    blocks: int = 0
    audits: int = 0
    by_stage: dict[str, int] = Field(default_factory=dict)
    by_rule: dict[str, int] = Field(default_factory=dict)


class ToolCallVerdict(BaseModel):
    tool_name: str
    tier: ToolTier
    args_passed: dict[str, Any] = Field(default_factory=dict)
    args_check: Literal["pass", "block", "warn"]
    permission_check: Literal["pass", "block"]
    decision: ToolDecision
    reason: str


class ToolManifestEntry(BaseModel):
    name: str
    description: str
    tier: ToolTier
    parameters: dict[str, Any] = Field(default_factory=dict)
    danger_patterns: list[str] = Field(default_factory=list)


class RAGAuditRecord(BaseModel):
    query: str
    chunks_returned: int
    total_available: int
    similarity_scores: list[float] = Field(default_factory=list)
    guard_triggered: bool = False
    guard_reason: str | None = None
    action: Literal["allow", "block", "truncate"] = "allow"

    @computed_field
    @property
    def return_ratio(self) -> float:
        if self.total_available <= 0:
            return 0.0
        return self.chunks_returned / self.total_available


class AgentStep(BaseModel):
    step_index: int
    thought: str = ""
    tool_call: str | None = None
    tool_args: dict[str, Any] | None = None
    guardrail_intervention: bool = False
    final_action: Literal[
        "tool_call",
        "refusal",
        "allowed_audited",
        "text_response",
    ]
    rag_triggered: bool = False
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SessionSecurityReport(BaseModel):
    session_id: str
    steps: list[AgentStep] = Field(default_factory=list)
    total_steps: int = 0
    guardrail_blocks: int = 0
    tools_called: int = 0
    tools_blocked: int = 0
    rag_retrievals: int = 0
    rag_dump_alerts: int = 0
    severity_score: int = 0

    @model_validator(mode="after")
    def derive_counts(self) -> "SessionSecurityReport":
        self.total_steps = len(self.steps)
        self.guardrail_blocks = sum(
            1
            for step in self.steps
            if step.guardrail_intervention and step.final_action == "refusal"
        )
        self.tools_called = sum(1 for step in self.steps if step.tool_call)
        self.tools_blocked = sum(
            1 for step in self.steps if step.tool_call and step.final_action == "refusal"
        )
        self.rag_retrievals = sum(1 for step in self.steps if step.rag_triggered)
        self.rag_dump_alerts = sum(
            1
            for step in self.steps
            if step.rag_triggered and step.guardrail_intervention
        )
        self.severity_score = min(
            100,
            self.guardrail_blocks * 50
            + self.tools_blocked * 25
            + self.rag_dump_alerts * 25,
        )
        return self


class AttackResult(BaseModel):
    run_id: str
    probe: str
    category: AttackCategory
    variant: str
    prompt: str
    response: str
    blocked: bool
    guard_triggered: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    latency_ms: int = Field(ge=0)


class EvalSummary(BaseModel):
    total_attacks: int
    blocked: int
    pass_rate: float
    by_category: dict[str, dict[str, float | int]] = Field(default_factory=dict)
    avg_latency_ms: int = 0


class EvalRun(BaseModel):
    run_id: str
    adapter: Literal["garak", "promptfoo", "local"]
    guard_mode: Literal["on", "off", "audit"]
    probes: list[str]
    status: EvalStatus
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    finished_at: datetime | None = None
    results: list[AttackResult] = Field(default_factory=list)
    summary: EvalSummary | None = None

    @model_validator(mode="after")
    def derive_summary(self) -> "EvalRun":
        if self.summary is not None or not self.results:
            return self

        total = len(self.results)
        blocked = sum(1 for result in self.results if result.blocked)
        by_category: dict[str, dict[str, float | int]] = {}
        for category in AttackCategory:
            category_results = [
                result for result in self.results if result.category == category
            ]
            if not category_results:
                continue
            category_total = len(category_results)
            category_blocked = sum(1 for result in category_results if result.blocked)
            by_category[category.value] = {
                "total": category_total,
                "blocked": category_blocked,
                "pass_rate": (category_total - category_blocked) / category_total,
            }

        self.summary = EvalSummary(
            total_attacks=total,
            blocked=blocked,
            pass_rate=(total - blocked) / total,
            by_category=by_category,
            avg_latency_ms=sum(result.latency_ms for result in self.results) // total,
        )
        return self


class ComparisonResult(BaseModel):
    baseline_run_id: str
    guarded_run_id: str
    baseline_rate: float
    guarded_rate: float
    reduction_pct: float
    by_category: dict[str, dict[str, float]] = Field(default_factory=dict)
