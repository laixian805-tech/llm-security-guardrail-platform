"""策略版本管理：版本创建、原子激活与按活跃版本确定性求值。

evaluate 记录实际生效的 policy_version；没有活跃版本时拒绝求值，不静默
回退到写死的版本号。激活是原子操作：旧版本停用与新版本生效同一事务。
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from domain import PolicyDecision, PolicyRuleSet, PolicyStatus
from domain.evidence import EvidenceRef
from services.ingestion_service import IngestError, reject_secrets
from storage.governance_repositories import GovernanceRepository

NOW = lambda: datetime.now(timezone.utc)
MAX_RULES = 32
DECISION_TTL = timedelta(minutes=10)


class PolicyService:
    def __init__(self, storage, repo: GovernanceRepository):
        self.storage = storage
        self.repo = repo

    def create(self, body, actor_id: str) -> PolicyRuleSet:
        reject_secrets(body)
        if set(body) - {"policy_version", "rules"}:
            raise IngestError("invalid_policy_version_input")
        version = body.get("policy_version")
        if not isinstance(version, str) or not (0 < len(version) <= 80):
            raise IngestError("invalid_policy_version")
        rules = body.get("rules")
        if not isinstance(rules, list) or not (1 <= len(rules) <= MAX_RULES):
            raise IngestError("invalid_policy_rules")
        if len({rule.get("rule_id") for rule in rules}) != len(rules):
            raise IngestError("duplicate_rule_id")
        model = PolicyRuleSet.model_validate({
            "policy_version": version, "rules": rules, "status": PolicyStatus.DRAFT,
            "created_by": actor_id, "created_at": NOW(),
        })
        self.repo.create(model)
        return model

    def get(self, policy_version: str) -> PolicyRuleSet | None:
        return self.repo.get(PolicyRuleSet, policy_version)

    def list(self) -> list[PolicyRuleSet]:
        return self.repo.list(PolicyRuleSet)

    def active(self) -> PolicyRuleSet | None:
        with self.storage.connection() as c:
            row = c.execute("SELECT * FROM policy_versions WHERE status='active'").fetchone()
        return self.repo.decode(PolicyRuleSet, row)

    def activate(self, policy_version: str, actor_id: str) -> PolicyRuleSet:
        model = self.get(policy_version)
        if not model:
            raise IngestError("unknown_policy_version", 404)
        if model.status is PolicyStatus.RETIRED:
            raise IngestError("retired_policy_version_cannot_activate", 409)
        if model.status is PolicyStatus.ACTIVE:
            return model
        stamp = NOW().isoformat()
        with self.storage._lock, self.storage.connection() as c:
            current = c.execute("SELECT policy_version FROM policy_versions WHERE status='active'").fetchone()
            if current and current["policy_version"] != policy_version:
                c.execute("UPDATE policy_versions SET status='retired', retired_at=? WHERE policy_version=?",
                          (stamp, current["policy_version"]))
                self.repo.record_transition(c, "policy_versions", current["policy_version"],
                                            "active", "retired", actor_id, "activate_other")
            c.execute("UPDATE policy_versions SET status='active', activated_at=? WHERE policy_version=?",
                      (stamp, policy_version))
            self.repo.record_transition(c, "policy_versions", policy_version,
                                        model.status.value, "active", actor_id, "activate")
        return self.get(policy_version)

    def rollback(self, policy_version: str, actor_id: str, reason: str | None) -> PolicyRuleSet:
        """回滚到某个历史版本（含 retired）。

        ``activate`` 只允许 draft → active，是"启用新版本"的语义；把 retired
        版本也放进去会让"废弃"失去意义。但线上误激活一个激进版本时必须有退路，
        所以单开一条：允许 retired → active，代价是**必须写清回滚原因**，并在
        迁移记录里用 ``rollback`` 与普通 ``activate`` 区分开，事后能查到是谁、
        为什么退回去。
        """
        model = self.get(policy_version)
        if not model:
            raise IngestError("unknown_policy_version", 404)
        if not isinstance(reason, str) or not reason.strip():
            raise IngestError("rollback_reason_required", 400)
        if model.status is PolicyStatus.ACTIVE:
            # 已经是活跃版本：幂等返回，不重复写迁移记录。
            return model
        stamp = NOW().isoformat()
        with self.storage._lock, self.storage.connection() as c:
            current = c.execute("SELECT policy_version FROM policy_versions WHERE status='active'").fetchone()
            if current and current["policy_version"] != policy_version:
                c.execute("UPDATE policy_versions SET status='retired', retired_at=? WHERE policy_version=?",
                          (stamp, current["policy_version"]))
                self.repo.record_transition(c, "policy_versions", current["policy_version"],
                                            "active", "retired", actor_id, "rollback_other")
            # retired_at 必须清掉，否则会出现 active 且 retired_at 非空的矛盾状态。
            c.execute("UPDATE policy_versions SET status='active', activated_at=?, retired_at=NULL"
                      " WHERE policy_version=?", (stamp, policy_version))
            self.repo.record_transition(c, "policy_versions", policy_version,
                                        model.status.value, "active", actor_id, "rollback",
                                        {"reason": reason.strip()})
        return self.get(policy_version)

    def evaluate(self, assessment, subject_kind: str, subject_id: str) -> PolicyDecision:
        version = self.active()
        if version is None:
            raise IngestError("no_active_policy", 500)
        peak = max(assessment.intrinsic_risk, assessment.runtime_risk, assessment.exposure_risk)
        floors = {
            "intrinsic_risk_min": assessment.intrinsic_risk,
            "runtime_risk_min": assessment.runtime_risk,
            "exposure_risk_min": assessment.exposure_risk,
        }
        matched = next((rule for rule in version.rules if self._matches(rule, floors, peak)), None)
        if matched is None:
            raise IngestError("policy_rule_set_has_no_match", 500)
        return PolicyDecision(
            decision_id="decision_" + uuid.uuid4().hex,
            action=matched.action,
            policy_version=version.policy_version,
            subject_kind=subject_kind,
            subject_id=subject_id,
            reason=f"{matched.rule_id}: {matched.reason}",
            evidence_refs=[EvidenceRef(kind="risk_assessment", uri=assessment.assessment_id),
                           EvidenceRef(kind="policy_version", uri=version.policy_version)],
            enforcement_expected=False,
            created_at=NOW(),
            expires_at=NOW() + DECISION_TTL,
        )

    @staticmethod
    def _matches(rule, floors: dict, peak: float) -> bool:
        if any(value < getattr(rule, key) for key, value in floors.items() if getattr(rule, key) is not None):
            return False
        if rule.any_dimension_above is not None and peak <= rule.any_dimension_above:
            return False
        if rule.peak_at_most is not None and peak > rule.peak_at_most:
            return False
        return True


def seed_default(storage) -> None:
    """没有策略版本时播种内置默认版本，保证 evaluate 始终有生效规则。"""
    from domain import default_rule_set

    service = PolicyService(storage, GovernanceRepository(storage))
    if service.active() is None:
        service.repo.create(default_rule_set())
