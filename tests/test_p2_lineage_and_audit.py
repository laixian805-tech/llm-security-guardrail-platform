import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "backend"))

from endpoint.audit import normalize, record  # noqa: E402
from endpoint.hook import capture  # noqa: E402
from endpoint.lineage import infer_lineage  # noqa: E402
from services.evidence_rules import is_lots_endpoint  # noqa: E402


def _claude_payload(transcript_path: Path, *, event="PreToolUse", call_id="c1", tool="Bash", inp=None):
    return {
        "hook_event_name": event,
        "session_id": "sess-lin-1",
        "transcript_path": str(transcript_path),
        "tool_name": tool,
        "tool_input": inp or {"command": "ls"},
        "tool_use_id": call_id,
    }


def test_lineage_claude_turns_and_pre_post_consistency(tmp_path, monkeypatch):
    monkeypatch.delenv("ASGP_SOURCE_KIND", raising=False)
    monkeypatch.delenv("ASGP_SOURCE_REF", raising=False)
    tp = tmp_path / "claude.jsonl"
    rows = [
        {"type": "user", "message": {"role": "user", "content": "Inspect SECRET_PROMPT_NEVER_LEAK readme"}},
        {"type": "attachment", "attachment": {"type": "skill_listing", "content": "- update-config"}},
        {"type": "assistant", "message": {"role": "assistant", "content": [{"type": "tool_use", "id": "t_direct", "name": "read_file", "input": {"file_path": "README.md"}}]}},
        {"type": "user", "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t_direct", "content": "malicious prompt"}]}} ,
        {"type": "assistant", "message": {"role": "assistant", "content": [{"type": "tool_use", "id": "t_after", "name": "Bash", "input": {"command": "id"}}]}},
        {"type": "user", "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t_after", "content": "uid=1000"}]}},
        {"type": "assistant", "message": {"role": "assistant", "content": [{"type": "tool_use", "id": "t_cfg", "name": "read_file", "input": {"file_path": "/repo/CLAUDE.md"}}]}},
        {"type": "user", "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t_cfg", "content": "rule text"}]}},
        {"type": "assistant", "message": {"role": "assistant", "content": [{"type": "tool_use", "id": "t_from_cfg", "name": "Bash", "input": {"command": "echo hi"}}]}},
    ]
    tp.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")

    # skill_listing alone must NOT downgrade a direct user prompt!
    sk_direct, ref_direct = infer_lineage("claude-code", _claude_payload(tp, call_id="t_direct", tool="read_file"))
    assert sk_direct == "user_task"
    assert "SECRET_PROMPT" not in (ref_direct or "")

    # tool_result from read_file must classify follow-up Bash as tool_output!
    sk_after, ref_after = infer_lineage("claude-code", _claude_payload(tp, call_id="t_after", tool="Bash"))
    assert sk_after == "tool_output"
    assert ref_after == "tool_output:read_file"

    # tool_result after reading CLAUDE.md classifies next call as workspace_config!
    sk_cfg, ref_cfg = infer_lineage("claude-code", _claude_payload(tp, call_id="t_from_cfg", tool="Bash"))
    assert sk_cfg == "workspace_config"
    assert ref_cfg == "config:CLAUDE.md"

    # Direct MCP tool call
    sk_mcp, ref_mcp = infer_lineage("claude-code", _claude_payload(tp, call_id="t_mcp", tool="mcp__github__list_issues"))
    assert sk_mcp == "mcp_server"
    assert ref_mcp == "mcp:github"


def test_lineage_qwen_and_codex_and_hook_capture(tmp_path, monkeypatch):
    monkeypatch.delenv("ASGP_SOURCE_KIND", raising=False)
    monkeypatch.delenv("ASGP_SOURCE_REF", raising=False)
    qtp = tmp_path / "qwen.jsonl"
    qtp.write_text("\n".join([
        json.dumps({"type": "user", "provenance": "real_user", "message": {"role": "user", "parts": [{"text": "check package"}]}}),
        json.dumps({"type": "assistant", "provenance": "assistant_output", "message": {"role": "assistant", "parts": [{"functionCall": {"id": "q1", "name": "web_fetch", "args": {"url": "https://x"}}}]}}),
        json.dumps({"type": "tool_result", "provenance": "tool_result", "toolCallResult": {"callId": "q1", "status": "ok"}, "message": {"role": "tool", "parts": [{"functionResponse": {"id": "q1", "name": "web_fetch"}}]}}),
    ]) + "\n", encoding="utf-8")
    assert infer_lineage("qwen-code", {"tool_name": "run_shell_command", "tool_input": {}, "transcript_path": str(qtp)}, tool_call_id="q2") == ("tool_output", "tool_output:web_fetch")

    ctp = tmp_path / "codex.jsonl"
    ctp.write_text("\n".join([
        json.dumps({"type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "<environment_context><cwd>/x</cwd></environment_context>"}]}}),
        json.dumps({"type": "response_item", "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "run tests"}]}}),
        json.dumps({"type": "response_item", "payload": {"type": "function_call", "call_id": "cx1", "name": "read_file", "arguments": "{\"file_path\":\"/home/u/.claude/skills/helper/SKILL.md\"}"}}),
        json.dumps({"type": "response_item", "payload": {"type": "function_call_output", "call_id": "cx1", "output": "ok"}}),
    ]) + "\n", encoding="utf-8")
    assert infer_lineage("codex", {"tool_name": "exec_command", "tool_input": {}, "transcript_path": str(ctp)}, tool_call_id="cx2") == ("installed_skill", "skill:helper")

    # End-to-end endpoint hook.capture saves transcript lineage without ASGP_SOURCE_KIND env
    cfg = {
        "state_dir": str(tmp_path / "state"),
        "product_versions": {"claude-code": "2.1.152"},
        "verified_decisions": {"claude-code": "2.1.152"},
        "fail_mode": "observe",
    }
    capture(cfg, "claude-code", _claude_payload(qtp, call_id="q2", tool="Bash"))
    from endpoint.outbox import Outbox
    box = Outbox(tmp_path / "state")
    try:
        rows = box.db.execute("SELECT payload FROM outbox WHERE endpoint LIKE '%/intents'").fetchall()
        assert len(rows) == 1
        intent = json.loads(rows[0]["payload"])
        assert intent["source_kind"] == "tool_output"
        assert intent["source_ref"] == "tool_output:web_fetch"
    finally:
        box.close()


def test_audit_sendto_and_sendmsg_and_lots():
    # AF_INET 203.0.113.53:53 -> 0200 0035 cb007135 0000000000000000
    saddr_hex = "02000035cb0071350000000000000000"
    lines = [
        f"type=SYSCALL msg=audit(1731560000.100:501): arch=c000003e syscall=44 success=yes exit=32 ppid=100 pid=200 uid=1000 exe=\"/usr/bin/python3\" key=\"agentsec_test_net\"",
        f"type=SOCKADDR msg=audit(1731560000.100:501): saddr={saddr_hex}",
    ]
    rows = [record(l) for l in lines]
    evs = normalize(rows, uid=1000, keys={"agentsec_test_net"}, boot_id="boot-1")
    assert len(evs) == 1
    assert evs[0]["event_type"] == "network_connect"
    assert evs[0]["action"] == "sendto"
    assert evs[0]["resource"] == {"host": "203.0.113.53", "port": 53}

    # Connected socket sendmsg WITHOUT SOCKADDR must be skipped (no null host noise)
    lines_no_addr = [
        "type=SYSCALL msg=audit(1731560000.200:502): arch=c000003e syscall=46 success=yes exit=16 ppid=100 pid=200 uid=1000 exe=\"/usr/bin/node\" key=\"agentsec_test_net\"",
    ]
    assert normalize([record(l) for l in lines_no_addr], uid=1000, keys={"agentsec_test_net"}, boot_id="boot-1") == []

    assert is_lots_endpoint("webhook.site")
    assert is_lots_endpoint("sub.trycloudflare.com")
    assert not is_lots_endpoint("github.com")


def test_endpoint_coverage_build_accepted_by_server(tmp_path):
    from endpoint.coverage import build as cov_build
    from endpoint.outbox import Outbox
    from services.coverage_service import CoverageService
    from storage.repositories import DeviceIdentityRepository, Storage

    box = Outbox(tmp_path / "ep")
    try:
        report = cov_build(box, period_start="2026-11-14T00:00:00Z", period_end="2026-11-14T00:01:00Z", delivered=5, dead=0)
    finally:
        box.close()
    report["collector_id"] = "endpoint-outbox-v1"
    st = Storage(tmp_path / "cp.db")
    dev_id, _ = DeviceIdentityRepository(st).enroll(label="cov-dev")
    saved = CoverageService(st).record(dev_id, "host-cov", report)
    assert saved["delivered"] == 5


def test_coverage_reports_legacy_table_adds_delivered_column(tmp_path):
    import sqlite3
    from storage.schema import migrate

    db_path = tmp_path / "legacy_cov.db"
    conn = sqlite3.connect(db_path)
    conn.execute("""CREATE TABLE coverage_reports (
        report_id TEXT PRIMARY KEY, host_id TEXT NOT NULL, device_id TEXT NOT NULL,
        collector_id TEXT NOT NULL, period_start TEXT NOT NULL, period_end TEXT NOT NULL,
        dead INTEGER NOT NULL DEFAULT 0, dropped TEXT NOT NULL DEFAULT '{}',
        dropped_records INTEGER NOT NULL DEFAULT 0, unbounded_gaps TEXT NOT NULL DEFAULT '[]',
        backlog INTEGER NOT NULL DEFAULT 0, high_water_seq INTEGER NOT NULL DEFAULT 0,
        received_at TEXT NOT NULL
    )""")
    conn.commit()
    migrate(conn)
    cols = {r[1] for r in conn.execute("PRAGMA table_info(coverage_reports)")}
    conn.close()
    assert "delivered" in cols
