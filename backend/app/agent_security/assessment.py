"""Separate detector actions from asset/behavior risk assessment labels."""

from __future__ import annotations

from .asset_identity import classify_carrier, legacy_provenance
from .models import RiskAssessment, ScanFinding, ScanVerdict, SecurityAction

_HIGH_RISK_RULES = {"S04", "S05", "S07", "S10", "R001", "R002", "R005"}
_RULE_WEIGHTS = {"critical": 25.0, "high": 15.0, "medium": 8.0}


def assess_findings(findings: list[ScanFinding]) -> tuple[RiskAssessment, str]:
    """Classify static observations without claiming a confirmed compromise.

    A rule's ``block`` action is an enforcement recommendation. It is not a
    malware verdict. Only analyst adjudication or corroborated intelligence
    may set ``confirmed_malicious``.
    """
    if not findings:
        return RiskAssessment.NO_FINDINGS, "no enabled static rule matched"
    rule_ids = {finding.rule_id for finding in findings}
    if rule_ids & _HIGH_RISK_RULES:
        return RiskAssessment.HIGH_RISK_CANDIDATE, (
            "high-impact static rule matched; inspect evidence and provenance"
        )
    return RiskAssessment.SUSPICIOUS, (
        "static finding requires review; this is not a malware adjudication"
    )


def score_findings(findings: list[ScanFinding], *, state: str = "installed") -> dict:
    """Score static evidence with a human-readable contribution breakdown.

    This is a triage score only. It never produces ``confirmed_malicious`` and
    never replaces the scanner's operational ``clean/alert/block`` verdict.
    """
    if not findings:
        return {"score": 0.0, "ranking_score": 0.0,
                "assessment": RiskAssessment.NO_FINDINGS.value,
                "reason": "no enabled static rule matched", "breakdown": []}

    by_rule: dict[str, list[ScanFinding]] = {}
    for finding in findings:
        by_rule.setdefault(finding.rule_id, []).append(finding)

    breakdown: list[dict] = []
    rule_weights: dict[str, float] = {}
    for rule_id, matches in sorted(by_rule.items()):
        finding = max(matches, key=lambda item: _severity_weight(item))
        weight = _severity_weight(finding)
        if len(matches) >= 3:
            weight *= 1.5
        if any(item.decoded for item in matches):
            weight *= 1.2
        rule_weights[rule_id] = weight
        breakdown.append({
            "signal": "rule",
            "rule_id": rule_id,
            "matches": len(matches),
            "weight": round(weight, 2),
            "reason": f"{finding.severity.value} static rule; decoded={any(item.decoded for item in matches)}",
        })

    base_score = sum(rule_weights.values())
    chain_bonus = 0.0
    if "S08" in rule_weights and ({"S11", "S20"} & rule_weights.keys()):
        chain_bonus += 20.0
        breakdown.append({"signal": "chain", "rule_ids": ["S08", "S11/S20"],
                          "weight": 20.0,
                          "reason": "sensitive read signal combined with external access"})
    if {"S04", "S06"}.issubset(rule_weights):
        chain_bonus += 15.0
        breakdown.append({"signal": "chain", "rule_ids": ["S04", "S06"],
                          "weight": 15.0,
                          "reason": "destructive command combined with privilege escalation"})

    provenance_penalty = 5.0 if "S16" in rule_weights else 0.0
    if provenance_penalty:
        breakdown.append({"signal": "provenance", "rule_id": "S16",
                          "weight": provenance_penalty,
                          "reason": "asset source is not registered"})

    activity_factor = 1.0 if state == "active" else (1.0 if state == "enabled" else 0.6)
    if activity_factor != 1.0:
        breakdown.append({"signal": "activity", "state": state,
                          "weight": activity_factor,
                          "reason": "not enabled; ranking adjustment only"})

    raw_score = base_score + chain_bonus + provenance_penalty
    score = max(0.0, min(100.0, raw_score))
    ranking_score = max(0.0, min(100.0, raw_score * activity_factor))
    assessment = (RiskAssessment.HIGH_RISK_CANDIDATE
                  if score >= 25 else RiskAssessment.SUSPICIOUS)
    return {
        "score": round(score, 2),
        "ranking_score": round(ranking_score, 2),
        "assessment": assessment.value,
        "reason": "weighted static evidence; analyst review required",
        "breakdown": breakdown,
    }


def _severity_weight(finding: ScanFinding) -> float:
    if finding.action == SecurityAction.AUDIT:
        return 3.0
    return _RULE_WEIGHTS.get(finding.severity.value, 3.0)


def scan_policy_verdict(findings: list[ScanFinding]) -> ScanVerdict:
    """Preserve the scanner's existing operational exit/block contract."""
    if any(finding.action == SecurityAction.BLOCK for finding in findings):
        return ScanVerdict.BLOCK
    if findings:
        return ScanVerdict.ALERT
    return ScanVerdict.CLEAN


def provenance_for_path(path: str) -> str:
    """Classify observed origin by path layout; provenance is not trust."""
    carrier = classify_carrier(path)
    if carrier.value == "unknown":
        normalized = "/" + path.replace("\\", "/").strip("/")
        if "/usr/lib/node_modules/" in normalized or "/usr/local/lib/node_modules/" in normalized:
            return "system_installed_cli_content"
        return "user_managed_content"
    return legacy_provenance(carrier)
