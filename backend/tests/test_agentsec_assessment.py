from app.agent_security.assessment import (
    assess_findings,
    provenance_for_path,
    scan_policy_verdict,
    score_findings,
)
from app.agent_security.models import RiskAssessment, ScanFinding, ScanVerdict, SecurityAction, Severity


def _finding(rule_id: str, severity: Severity, action: SecurityAction) -> ScanFinding:
    return ScanFinding(rule_id=rule_id, name=rule_id, severity=severity, action=action)


def test_scanner_policy_verdict_is_separate_from_risk_assessment() -> None:
    hidden_instruction = [_finding("S02", Severity.HIGH, SecurityAction.ALERT)]
    assert scan_policy_verdict(hidden_instruction) == ScanVerdict.ALERT
    assert assess_findings(hidden_instruction)[0] == RiskAssessment.SUSPICIOUS

    shell_execution = [_finding("S05", Severity.CRITICAL, SecurityAction.BLOCK)]
    assert scan_policy_verdict(shell_execution) == ScanVerdict.BLOCK
    assert assess_findings(shell_execution)[0] == RiskAssessment.HIGH_RISK_CANDIDATE

    assert assess_findings([])[0] == RiskAssessment.NO_FINDINGS


def test_provenance_names_plugin_cache_and_synthetic_content() -> None:
    assert provenance_for_path(
        "/home/lab/.codex/.tmp/plugins/plugins/vendor/skills/tool/SKILL.md"
    ) == "codex_plugin_cache"
    assert provenance_for_path("/home/lab/lab/agentsec-assets/skills/fake/SKILL.md") == "synthetic_test"


def test_risk_score_explains_rule_and_chain_contributions() -> None:
    sensitive = _finding("S08", Severity.CRITICAL, SecurityAction.BLOCK)
    external = _finding("S20", Severity.HIGH, SecurityAction.ALERT)
    alone = score_findings([sensitive], state="enabled")
    chained = score_findings([sensitive, external], state="active")

    assert alone["score"] == 25
    assert not any(item["signal"] == "chain" for item in alone["breakdown"])
    assert chained["score"] == 60
    assert chained["ranking_score"] == 60
    assert any(item["signal"] == "chain" and item["weight"] == 20
               for item in chained["breakdown"])
    assert chained["assessment"] == RiskAssessment.HIGH_RISK_CANDIDATE.value


def test_activity_only_changes_ranking_score_and_never_confirms_malicious() -> None:
    finding = _finding("S05", Severity.CRITICAL, SecurityAction.BLOCK)
    installed = score_findings([finding], state="installed")
    active = score_findings([finding], state="active")

    assert installed["score"] == active["score"] == 25
    assert installed["ranking_score"] == 15
    assert active["ranking_score"] == 25
    assert installed["assessment"] != RiskAssessment.CONFIRMED_MALICIOUS.value


def test_sensitive_path_mention_is_not_itself_confirmed_or_high_risk() -> None:
    finding = [_finding("S08", Severity.CRITICAL, SecurityAction.BLOCK)]
    assessment, _ = assess_findings(finding)
    assert assessment == RiskAssessment.SUSPICIOUS
