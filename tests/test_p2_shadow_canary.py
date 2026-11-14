import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from endpoint.hook import capture  # noqa: E402
from endpoint.outbox import Outbox  # noqa: E402
from test_console_auth import api, admin_token, call  # noqa: E402
from test_v1_ingest import execution, setup_device  # noqa: E402


def test_endpoint_shadow_deny_never_blocks_and_never_leaks_pattern(tmp_path):
    cfg_obs = {
        "state_dir": str(tmp_path / "obs"),
        "product_versions": {"claude-code": "2.1.152"},
        "verified_decisions": {"claude-code": "2.1.152"},
        "fail_mode": "observe",
        "shadow_deny_patterns": [{"rule_id": "shadow-pipe-sh", "pattern": "SHADOW_SECRET_CMD"}],
    }
    payload = {
        "hook_event_name": "PreToolUse",
        "session_id": "s-shadow-1",
        "tool_name": "Bash",
        "tool_input": {"command": "echo SHADOW_SECRET_CMD"},
        "tool_use_id": "call-shadow-1",
    }
    directive = capture(cfg_obs, "claude-code", payload)
    assert directive == ""
    box = Outbox(tmp_path / "obs")
    try:
        row = box.db.execute("SELECT payload FROM outbox WHERE endpoint LIKE '%/intents'").fetchone()
        intent = json.loads(row["payload"])
        assert intent["decision"] == "not_applicable"
        assert "SHADOW_SECRET_CMD" not in intent["params_summary"]
        summary = json.loads(intent["params_summary"])
        assert summary["shadow_would_block"] is True
        assert summary["shadow_matches"][0]["rule_id"] == "shadow-pipe-sh"
    finally:
        box.close()

    # In fail_mode=deny, shadow_deny_patterns still returns allow (non-blocking)
    cfg_deny = dict(cfg_obs, state_dir=str(tmp_path / "den"), fail_mode="deny")
    out_json = json.loads(capture(cfg_deny, "claude-code", payload))
    assert out_json["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_scoped_canary_policy_shadow_eval_and_summary(api, admin_token):
    dev_canary = setup_device(api, admin_token, "canary-01")
    dev_shadow = setup_device(api, admin_token, "shadow-01")

    # Upload an intent carrying shadow_would_block metadata
    ex = execution("exec_shadow_obs")
    ex["product"] = "claude-code"
    ex["product_version"] = "2.1.152"
    call(api.base, "POST", "/api/v1/executions", token=dev_shadow["token"], body=ex).raise_for_status()
    call(
        api.base,
        "POST",
        f"/api/v1/executions/{ex['execution_id']}/intents",
        token=dev_shadow["token"],
        body={
            "intent_id": "int_shadow_1",
            "tool_call_id": "tc_sh_1",
            "tool_name": "Bash",
            "hook_event_type": "pre_tool_use",
            "decision": "not_applicable",
            "params_summary": json.dumps({
                "parameter_names": ["command"],
                "values_omitted": True,
                "shadow_would_block": True,
                "shadow_matches": [{"rule_id": "shadow-pipe-sh", "pattern_sha256": "deadbeef1234"}],
            }),
            "params_sha256": "a" * 64,
            "redaction_applied": True,
            "occurred_at": "2026-11-14T08:00:00+00:00",
        },
    ).raise_for_status()

    # Create risk assessment (exposure_risk == 80 via privileged flag)
    risk = call(
        api.base,
        "POST",
        "/api/v1/risk-assessments",
        token=admin_token,
        body={"exposure": {"privileged": True}},
    ).json()

    # Create canary + shadow policy version
    call(
        api.base,
        "POST",
        "/api/v1/policies/versions",
        token=admin_token,
        body={
            "policy_version": "policy-canary-v1",
            "rules": [
                {
                    "rule_id": "shadow-canary-host",
                    "action": "block",
                    "reason": "shadow dry-run on shadow host",
                    "exposure_risk_min": 50,
                    "target_host_ids": ["host_shadow-01"],
                    "shadow_only": True,
                },
                {
                    "rule_id": "canary-ring1-claude",
                    "action": "block",
                    "reason": "ring1 block for claude-code on canary-01",
                    "exposure_risk_min": 50,
                    "target_host_ids": ["host_canary-01"],
                    "target_products": ["claude-code"],
                },
                {
                    "rule_id": "safe-baseline-audit",
                    "action": "audit",
                    "reason": "baseline non-blocking observe",
                },
            ],
        },
    ).raise_for_status()
    call(api.base, "POST", "/api/v1/policies/versions/policy-canary-v1/activate", token=admin_token, body={}).raise_for_status()

    # 1. shadow host gets AUDIT with [SHADOW would=block]
    dec_shadow = call(
        api.base,
        "POST",
        "/api/v1/policies/evaluate",
        token=admin_token,
        body={"assessment_id": risk["assessment_id"], "subject_kind": "asset", "subject_id": "a1", "host_id": "host_shadow-01", "product": "claude-code"},
    ).json()
    assert dec_shadow["action"] == "audit"
    assert "[SHADOW would=block]" in dec_shadow["reason"]

    # 2. canary host + matching product gets BLOCK
    dec_ring1 = call(
        api.base,
        "POST",
        "/api/v1/policies/evaluate",
        token=admin_token,
        body={"assessment_id": risk["assessment_id"], "subject_kind": "asset", "subject_id": "a1", "host_id": "host_canary-01", "product": "claude-code"},
    ).json()
    assert dec_ring1["action"] == "block"

    # 3. canary host + non-canary product AND general host fall back to safe-baseline-audit
    dec_other_prod = call(
        api.base,
        "POST",
        "/api/v1/policies/evaluate",
        token=admin_token,
        body={"assessment_id": risk["assessment_id"], "subject_kind": "asset", "subject_id": "a1", "host_id": "host_canary-01", "product": "codex"},
    ).json()
    assert dec_other_prod["action"] == "audit"
    assert dec_other_prod["reason"].startswith("safe-baseline-audit:")

    dec_prod_fleet = call(
        api.base,
        "POST",
        "/api/v1/policies/evaluate",
        token=admin_token,
        body={"assessment_id": risk["assessment_id"], "subject_kind": "asset", "subject_id": "a1", "host_id": "host_prod-99", "product": "claude-code"},
    ).json()
    assert dec_prod_fleet["action"] == "audit"

    # 4. shadow-summary endpoint aggregates both endpoint shadow intents and policy shadow decisions
    summary = call(api.base, "GET", "/api/v1/policies/shadow-summary", token=admin_token).json()
    assert summary["endpoint_shadow_hits"] == 1
    assert summary["policy_shadow_decisions"] == 1
    assert summary["by_product"] == {"claude-code": 1}

    # 5. Rollback to default policy cleanly
    rb = call(
        api.base,
        "POST",
        "/api/v1/policies/versions/policy-v1/rollback",
        token=admin_token,
        body={"reason": "canary review complete"},
    )
    assert rb.status_code == 200
