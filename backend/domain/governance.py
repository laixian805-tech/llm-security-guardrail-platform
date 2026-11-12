"""P3 风险、策略、准入和事件工单契约。

这些记录彼此分离：风险评估不等于策略动作，策略动作不等于产品已经
执行，Incident 也不等于单条 Finding。
"""
from __future__ import annotations

from datetime import datetime, timezone

from pydantic import Field, model_validator

from domain.asset import StrictModel
from domain.enums import AdmissionState, Confidence, IncidentStatus, PolicyAction, PolicyStatus, Severity
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
    # 目标产品决定落到哪个真实加载目录；None 表示只进平台托管存储，
    # 此时不得声称产品已加载该包。
    product_id: str | None = None
    # 产品侧安装结果：实际目录、回滚凭据与会话级加载结论。
    # product_loaded 为 None 表示"未验证"（探测不可用），False 表示产品
    # 不认识这个技能；三者都不等于已生效。product_verification 记录判定等级。
    product_target: str | None = None
    product_rollback_ref: str | None = None
    product_loaded: bool | None = None
    product_verification: str | None = None
    state: AdmissionState = AdmissionState.CHECK
    approved_by: str | None = None
    observed_content_hash: str | None = None
    # 安装器回滚凭据：None 表示本事务从未提交；否则是提交前快照名，
    # first_install 表示首次安装没有可恢复的旧版本。
    rollback_ref: str | None = None
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


class PolicyRule(StrictModel):
    """一条确定性策略规则。

    规则按列表顺序首个命中者胜出；所有给出的条件都满足才算命中。不同量纲
    的风险分数在规则里各自比较，不在代码里相加。条件字段为 None 表示该
    维度不参与判断，因此不带任何条件的规则是无条件兜底规则。
    """

    rule_id: str = Field(min_length=1, max_length=80)
    action: PolicyAction
    reason: str = Field(min_length=1, max_length=300)
    intrinsic_risk_min: float | None = Field(default=None, ge=0, le=100)
    runtime_risk_min: float | None = Field(default=None, ge=0, le=100)
    exposure_risk_min: float | None = Field(default=None, ge=0, le=100)
    any_dimension_above: float | None = Field(default=None, ge=0, le=100)
    peak_at_most: float | None = Field(default=None, ge=0, le=100)


class PolicyRuleSet(StrictModel):
    """一个策略版本；同一时刻只有一个 active 版本参与求值。"""

    policy_version: str = Field(min_length=1, max_length=80)
    rules: list[PolicyRule] = Field(min_length=1, max_length=32)
    status: PolicyStatus = PolicyStatus.DRAFT
    created_by: str = Field(min_length=1)
    created_at: datetime
    activated_at: datetime | None = None
    retired_at: datetime | None = None

    @model_validator(mode="after")
    def _status_timestamps_must_agree(self) -> PolicyRuleSet:
        if self.status is PolicyStatus.ACTIVE and self.activated_at is None:
            raise ValueError("active policy version requires activated_at")
        if self.status is PolicyStatus.DRAFT and (self.activated_at or self.retired_at):
            raise ValueError("draft policy version cannot carry activation timestamps")
        if self.status is PolicyStatus.RETIRED and self.retired_at is None:
            raise ValueError("retired policy version requires retired_at")
        return self


DEFAULT_POLICY_VERSION = "policy-v1"


def default_rule_set(now: datetime | None = None) -> PolicyRuleSet:
    """内置默认策略：与 P3 首片的确定性阈值一致，作为已激活版本播种。"""
    stamp = now or datetime.now(timezone.utc)
    return PolicyRuleSet(
        policy_version=DEFAULT_POLICY_VERSION,
        rules=[
            PolicyRule(rule_id="block-critical-intrinsic", action=PolicyAction.BLOCK,
                       reason="intrinsic risk at or above 90", intrinsic_risk_min=90),
            PolicyRule(rule_id="confirm-high-intrinsic", action=PolicyAction.CONFIRM,
                       reason="intrinsic risk at or above 70", intrinsic_risk_min=70),
            PolicyRule(rule_id="confirm-exposed", action=PolicyAction.CONFIRM,
                       reason="exposure risk at or above 80", exposure_risk_min=80),
            PolicyRule(rule_id="audit-observed", action=PolicyAction.AUDIT,
                       reason="any risk dimension observed", any_dimension_above=0),
            PolicyRule(rule_id="allow-clean", action=PolicyAction.ALLOW,
                       reason="no risk dimension observed", peak_at_most=0),
        ],
        status=PolicyStatus.ACTIVE,
        created_by="system",
        created_at=stamp,
        activated_at=stamp,
    )


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
