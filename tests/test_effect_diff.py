"""指令来源谱系 × 预期/真实 OS 副作用差分测试。"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from test_console_auth import api, admin_token, call
from test_v1_ingest import setup_device


def _ts(offset_sec: int = 0) -> str:
    base = datetime(2026, 11, 13, 8, 0, 0, tzinfo=timezone.utc)
    return (base + timedelta(seconds=offset_sec)).isoformat()


def _create_execution(api, device_token: str, execution_id: str) -> None:
    resp = call(
        api.base,
        "POST",
        "/api/v1/executions",
        token=device_token,
        body={
            "execution_id": execution_id,
            "product": "claude-code",
            "product_version": "2.1.152",
            "session_id": f"sess_{execution_id}",
            "started_at": _ts(0),
            "outcome": "running",
        },
    )
    assert resp.status_code == 200, resp.text


def _post_intent(api, device_token: str, execution_id: str, payload: dict) -> None:
    resp = call(
        api.base,
        "POST",
        f"/api/v1/executions/{execution_id}/intents",
        token=device_token,
        body=payload,
    )
    assert resp.status_code == 200, resp.text


def _post_events(api, device_token: str, events: list[dict]) -> None:
    resp = call(
        api.base,
        "POST",
        "/api/v1/runtime-events:batch",
        token=device_token,
        body={"collector_id": "auditd-v1", "events": events},
    )
    assert resp.status_code == 200, resp.text


def _correlate(api, admin_token: str, execution_id: str) -> dict:
    resp = call(
        api.base,
        "POST",
        f"/api/v1/executions/{execution_id}/correlate",
        token=admin_token,
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def _effect_diff(api, admin_token: str, execution_id: str) -> dict:
    resp = call(
        api.base,
        "GET",
        f"/api/v1/executions/{execution_id}/effect-diff",
        token=admin_token,
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


class TestEffectDiff:
    def test_workspace_read_within_expected_has_zero_undeclared(self, api, admin_token):
        device = setup_device(api, admin_token, label="host_ed_1")
        _create_execution(api, device["token"], "exec_ok_1")
        _post_intent(
            api,
            device["token"],
            "exec_ok_1",
            {
                "intent_id": "int_ok_1",
                "tool_call_id": "tc_ok_1",
                "tool_name": "read_file",
                "hook_event_type": "pre_tool_use",
                "decision": "allow",
                "decision_reason": "workspace read",
                "params_summary": '{"parameter_names":["path"],"resource_hints":["~/proj/README.md"]}',
                "source_kind": "user_task",
                "source_ref": "prompt_01",
                "occurred_at": _ts(1),
            },
        )
        _post_events(
            api,
            device["token"],
            [
                {
                    "event_id": "ev_ok_1",
                    "execution_id": "exec_ok_1",
                    "intent_ref": "int_ok_1",
                    "event_type": "file_access",
                    "occurred_at": _ts(2),
                    "resource": {"path": "/home/lab/proj/README.md"},
                    "action": "openat",
                    "result": "ok",
                }
            ],
        )
        _correlate(api, admin_token, "exec_ok_1")
        diff = _effect_diff(api, admin_token, "exec_ok_1")
        assert diff["undeclared_count"] == 0
        assert diff["within_expected_count"] == 1
        assert diff["by_source_kind"] == {"user_task": 1}
        assert diff["items"][0]["verdict"] == "within_expected"
        assert diff["items"][0]["trust_tier"] == "high"

    def test_disguised_skill_sensitive_read_and_unexpected_network_are_caught(self, api, admin_token):
        device = setup_device(api, admin_token, label="host_ed_2")
        _create_execution(api, device["token"], "exec_mal_1")
        # 模型侧工具调用表面宣称读 package.json，但来自低信任 installed_skill，
        # OS 真实归因事件既读了 ~/.ssh/id_rsa 又外连了陌生公网 IP。
        _post_intent(
            api,
            device["token"],
            "exec_mal_1",
            {
                "intent_id": "int_mal_1",
                "tool_call_id": "tc_mal_1",
                "tool_name": "read_file",
                "hook_event_type": "pre_tool_use",
                "decision": "allow",
                "decision_reason": "allowed read",
                "params_summary": '{"parameter_names":["path"],"resource_hints":["~/proj/package.json"]}',
                "source_kind": "installed_skill",
                "source_ref": "skill_dep_helper",
                "occurred_at": _ts(1),
            },
        )
        _post_events(
            api,
            device["token"],
            [
                {
                    "event_id": "anchor_mal_1",
                    "execution_id": "exec_mal_1",
                    "intent_ref": "int_mal_1",
                    "event_type": "hook_anchor",
                    "occurred_at": _ts(1),
                    "process": {"pid": 4100, "ppid": 4000, "executable": "claude"},
                    "action": "tool_context",
                    "result": "observed",
                },
                {
                    "event_id": "ev_ssh_1",
                    "event_type": "file_access",
                    "occurred_at": _ts(2),
                    "process": {"pid": 4101, "ppid": 4100, "executable": "cat"},
                    "resource": {"path": "/home/lab/.ssh/id_rsa"},
                    "action": "openat",
                    "result": "ok",
                },
                {
                    "event_id": "ev_net_1",
                    "event_type": "network_connect",
                    "occurred_at": _ts(3),
                    "process": {"pid": 4102, "ppid": 4100, "executable": "curl"},
                    "resource": {"host": "45.33.32.156", "port": 443},
                    "action": "connect",
                    "result": "ok",
                },
            ],
        )
        _correlate(api, admin_token, "exec_mal_1")
        diff = _effect_diff(api, admin_token, "exec_mal_1")
        assert diff["undeclared_count"] == 2
        assert diff["within_expected_count"] == 0
        assert diff["by_source_kind"] == {"installed_skill": 1}
        verdicts = {item["event_id"]: item for item in diff["items"]}
        assert verdicts["ev_ssh_1"]["verdict"] == "undeclared_side_effect"
        assert verdicts["ev_ssh_1"]["trust_tier"] == "low"
        assert verdicts["ev_net_1"]["verdict"] == "undeclared_side_effect"

    def test_unattributed_events_remain_honestly_unattributed(self, api, admin_token):
        device = setup_device(api, admin_token, label="host_ed_3")
        _create_execution(api, device["token"], "exec_gap_1")
        _post_intent(
            api,
            device["token"],
            "exec_gap_1",
            {
                "intent_id": "int_gap_1",
                "tool_call_id": "tc_gap_1",
                "tool_name": "bash",
                "hook_event_type": "pre_tool_use",
                "decision": "not_applicable",
                "params_summary": '{"parameter_names":["command"]}',
                "source_kind": "mcp_server",
                "source_ref": "mcp_untrusted",
                "occurred_at": _ts(1),
            },
        )
        # 无 intent_ref、无进程谱系、无 resource_hints 的背景事件不得硬连。
        _post_events(
            api,
            device["token"],
            [
                {
                    "event_id": "ev_bg_1",
                    "event_type": "network_connect",
                    "occurred_at": _ts(2),
                    "process": {"pid": 9999, "ppid": 1, "executable": "systemd"},
                    "resource": {"host": "93.184.216.34", "port": 80},
                    "action": "connect",
                    "result": "ok",
                }
            ],
        )
        _correlate(api, admin_token, "exec_gap_1")
        diff = _effect_diff(api, admin_token, "exec_gap_1")
        assert diff["attributed_event_count"] == 0
        assert diff["unattributed_event_count"] == 1
        assert diff["undeclared_count"] == 0
        assert diff["items"][0]["verdict"] == "no_observed_effect"

    def test_post_tool_merge_preserves_source_provenance(self, api, admin_token):
        device = setup_device(api, admin_token, label="host_ed_4")
        _create_execution(api, device["token"], "exec_merge_1")
        _post_intent(
            api,
            device["token"],
            "exec_merge_1",
            {
                "intent_id": "int_m_1",
                "tool_call_id": "tc_m_1",
                "tool_name": "bash",
                "hook_event_type": "pre_tool_use",
                "decision": "allow",
                "decision_reason": "ok",
                "source_kind": "tool_output",
                "source_ref": "fetched_readme",
                "occurred_at": _ts(1),
            },
        )
        # PostToolUse 不带 source_kind/source_ref，合并后不应覆盖原有来源谱系。
        _post_intent(
            api,
            device["token"],
            "exec_merge_1",
            {
                "intent_id": "int_m_1_post",
                "tool_call_id": "tc_m_1",
                "tool_name": "bash",
                "hook_event_type": "post_tool_use",
                "decision": "not_applicable",
                "occurred_at": _ts(1),
                "ended_at": _ts(2),
                "product_result": "observed",
            },
        )
        diff = _effect_diff(api, admin_token, "exec_merge_1")
        assert diff["by_source_kind"] == {"tool_output": 1}
        assert diff["items"][0]["source_ref"] == "fetched_readme"

    def test_overview_reads_evaluation_without_error(self, api, admin_token):
        resp = call(api.base, "GET", "/api/v1/overview", token=admin_token)
        assert resp.status_code == 200
        ev = resp.json()["evaluation"]
        assert "effect_diff_scenarios" in ev
        assert "attribution_precision" in ev

    def test_process_start_event_is_classified_by_tool_category(self, api, admin_token):
        device = setup_device(api, admin_token, label="host_ed_5")
        _create_execution(api, device["token"], "exec_proc_1")
        _post_intent(
            api,
            device["token"],
            "exec_proc_1",
            {
                "intent_id": "int_p_read",
                "tool_call_id": "tc_p_read",
                "tool_name": "read_file",
                "hook_event_type": "pre_tool_use",
                "decision": "allow",
                "decision_reason": "ok",
                "source_kind": "installed_skill",
                "source_ref": "skill_sneaky",
                "occurred_at": _ts(1),
            },
        )
        _post_intent(
            api,
            device["token"],
            "exec_proc_1",
            {
                "intent_id": "int_p_exec",
                "tool_call_id": "tc_p_exec",
                "tool_name": "run_shell_command",
                "hook_event_type": "pre_tool_use",
                "decision": "allow",
                "decision_reason": "ok",
                "source_kind": "user_task",
                "source_ref": "task_ok",
                "occurred_at": _ts(4),
            },
        )
        _post_events(
            api,
            device["token"],
            [
                {
                    "event_id": "ev_ps_read",
                    "execution_id": "exec_proc_1",
                    "intent_ref": "int_p_read",
                    "event_type": "process_start",
                    "occurred_at": _ts(2),
                    "process": {"pid": 5101, "ppid": 5100, "executable": "/bin/sh"},
                    "action": "exec",
                    "result": "success",
                },
                {
                    "event_id": "ev_ps_exec",
                    "execution_id": "exec_proc_1",
                    "intent_ref": "int_p_exec",
                    "event_type": "process_start",
                    "occurred_at": _ts(5),
                    "process": {"pid": 5201, "ppid": 5200, "executable": "/bin/bash"},
                    "action": "exec",
                    "result": "success",
                },
            ],
        )
        _correlate(api, admin_token, "exec_proc_1")
        diff = _effect_diff(api, admin_token, "exec_proc_1")
        assert diff["undeclared_count"] == 1
        assert diff["within_expected_count"] == 1
        by_ev = {item["event_id"]: item["verdict"] for item in diff["items"]}
        assert by_ev["ev_ps_read"] == "undeclared_side_effect"
        assert by_ev["ev_ps_exec"] == "within_expected"
