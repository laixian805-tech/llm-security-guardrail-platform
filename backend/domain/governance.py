"""P3 风险、策略、准入和事件工单契约。

这些记录彼此分离：风险评估不等于策略动作，策略动作不等于产品已经
执行，Incident 也不等于单条 Finding。
"""
from __future__ import annotations

from datetime import datetime

from pydantic import Field, model_validator

from domain.asset import StrictModel
from domain.enums import AdmissionState, Confidence, IncidentStatus, PolicyAction, Severity
from domain.evidence import EvidenceRef


class RiskAssessment(StrictModel):
    assessment_id: str = Field(min_length=1)
    asset_id: str | None = None
    execution_id: str | None = None
    intrinsic_risk: float = Field(ge=0, le=100)
    runtime_risk: float = Field(ge=0, le=100)
    exposure_risk: float = Field(ge=0, le=100)
    confidence: Confidence = Confidence.UNKNOWN
    reasons: list[str] = Field(default_factory=list, max_length=32)
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    rule_version: str = Field(min_length=1)
    created_at: datetime
    updated_at: datetime


class PolicyDecision(StrictModel):
    decision_id: str = Field(min_length=1)
    action: PolicyAction
    policy_version: str = Field(min_length=1)
    subject_kind: str = Field(min_length=1)
    subject_id: str = Field(min_length=1)
    reason: str = Field(min_length=1, max_length=2048)
    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    enforcement_expected: bool = False
    created_at: datetime
    expires_at: datetime | None = None


class Admission(StrictModel):
    admission_id: str = Field(min_length=1)
    asset_instance_id: str = Field(min_length=1)
    content_hash: str = Field(min_length=1)
    state: AdmissionState = AdmissionState.CHECK
    approved_by: str | None = None
    observed_content_hash: str | None = None
    failure_reason: str | None = None
    transaction_id: str = Field(min_length=1)
    created_at: datetime
    updated_at: datetime

    @model_validator(mode="after")
    def _hash_must_match_when_verified(self) -> Admission:
        if self.state in (AdmissionState.VERIFIED, AdmissionState.RECONCILED):
            if self.observed_content_hash != self.content_hash:
                raise ValueError("verified admission requires matching content hash")
        return self


class Incident(StrictModel):
    incident_id: str = Field(min_length=1)
    status: IncidentStatus = IncidentStatus.OPEN
    severity: Severity = Severity.UNKNOWN
    title: str = Field(min_length=1, max_length=300)
    summary: str = Field(default="", max_length=4096)
    owner: str | None = None
    opened_at: datetime
    updated_at: datetime
    closed_at: datetime | None = None

    @model_validator(mode="after")
    def _closed_requires_time(self) -> Incident:
        if self.status is IncidentStatus.CLOSED and self.closed_at is None:
            raise ValueError("closed incident requires closed_at")
        if self.status is not IncidentStatus.CLOSED and self.closed_at is not None:
            raise ValueError("open incident cannot have closed_at")
        return self


class IncidentEvidence(StrictModel):
    incident_id: str = Field(min_length=1)
    evidence_kind: str = Field(min_length=1)
    evidence_id: str = Field(min_length=1)
    note: str = Field(default="", max_length=1024)
    added_at: datetime
