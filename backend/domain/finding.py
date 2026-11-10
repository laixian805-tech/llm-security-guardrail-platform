"""Finding 契约。

Finding 是检测器观察到的原始证据，不是 Risk Assessment，也不是
PolicyDecision。标准化只做映射，不丢弃上游规则 ID、版本、置信度和
原始报告引用。
"""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from domain.asset import StrictModel
from domain.enums import Confidence, FindingStatus, Severity
from domain.evidence import EvidenceRef


class Finding(StrictModel):
    finding_id: str = Field(min_length=1)
    detector_run_id: str = Field(min_length=1)
    # 无法关联逻辑资产或实例时留空，不用目标路径猜测填充。
    asset_id: str | None = None
    instance_id: str | None = None
    execution_id: str | None = None

    detector_id: str = Field(min_length=1)
    detector_version: str = Field(min_length=1)
    rule_id: str = Field(min_length=1)
    # 上游原始规则 ID 必须保留，便于回溯到引擎规则包。
    upstream_rule_id: str | None = None

    severity: Severity = Severity.UNKNOWN
    confidence: Confidence = Confidence.UNKNOWN
    title: str = Field(min_length=1)
    message: str = ""

    evidence_refs: list[EvidenceRef] = Field(default_factory=list)
    fingerprint: str = Field(min_length=1)
    status: FindingStatus = FindingStatus.NEW

    # 上游原始分数，仅作参考；不同引擎的分数不得相加。
    upstream_risk_score: float | None = None

    created_at: datetime
    updated_at: datetime
