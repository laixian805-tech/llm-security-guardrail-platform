from __future__ import annotations

from app.agent_security.poc import run_acceptance_poc


def test_acceptance_poc_checks_the_local_vertical_slice() -> None:
    report = run_acceptance_poc()

    assert report["schema_version"] == 2
    assert report["status"] == "passed"
    assert report["synthetic"] is True
    assert report["network_access"] is False
    assert report["production_touched"] is False
    assert report["enforcement_scope"] == (
        "local Hook decision only; Monitor observes and API ingests"
    )
    assert report["summary"] == {
        "passed": 10,
        "failed": 0,
        "total": 10,
    }
    assert {check["name"] for check in report["checks"]} == {
        "scanner_fixture_pair",
        "pre_execution_policy",
        "adapter_ask_deny_protocol_claude-code",
        "adapter_ask_deny_protocol_codex",
        "malformed_stdin_fail_closed_claude-code",
        "malformed_stdin_fail_closed_codex",
        "codex_mcp_matcher_negative_case",
        "hook_process_policy",
        "monitor_session_and_exfil_correlation",
        "api_event_session_timeline",
    }
    assert all({"product", "product_version", "adapter", "version_status"}
               <= set(check) for check in report["checks"])
    adapter_checks = [
        check for check in report["checks"]
        if check["version_status"] == "not_probed"
    ]
    assert {check["product"] for check in adapter_checks} == {
        "Claude Code", "Codex CLI",
    }
    assert all(check["product_version"] is None and check["adapter"]
               for check in adapter_checks)
