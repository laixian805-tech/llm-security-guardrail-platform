from __future__ import annotations

import json
from pathlib import Path

from app.agent_security.cli import main

FIXTURES = Path(__file__).parent / "fixtures" / "agentsec"


def _run(tmp_path: Path, argv: list[str]) -> int:
    import os

    # Save/restore: leaking AGENTSEC_HOME/HOME into later test modules breaks
    # state-dir resolution for everyone else in the same pytest process.
    saved = dict(os.environ)
    try:
        os.environ["AGENTSEC_DB_PATH"] = str(tmp_path / "agentsec.db")
        os.environ["AGENTSEC_HOME"] = str(tmp_path / "agentsec-home")
        os.environ["HOME"] = str(tmp_path / "home")
        (tmp_path / "home").mkdir(exist_ok=True)
        return main(argv)
    finally:
        os.environ.clear()
        os.environ.update(saved)


def test_scan_evil_skill_returns_block_exit_code(tmp_path: Path, capsys) -> None:
    code = _run(tmp_path, ["scan", str(FIXTURES / "evil-skill"), "--host", "d2-dev"])
    assert code == 2
    out = capsys.readouterr().out
    assert "BLOCK" in out and "S05" in out


def test_scan_registered_clean_skill_returns_zero(tmp_path: Path, capsys) -> None:
    assert _run(tmp_path, ["registry", "add", "--kind", "skill", "--name", "clean-skill",
                           "--path", str(FIXTURES / "clean-skill")]) == 0
    code = _run(tmp_path, ["scan", str(FIXTURES / "clean-skill"), "--host", "d2-dev"])
    assert code == 0
    assert "CLEAN" in capsys.readouterr().out


def test_scan_missing_path_returns_three(tmp_path: Path) -> None:
    assert _run(tmp_path, ["scan", str(tmp_path / "nope")]) == 3


def test_registry_add_list_remove(tmp_path: Path, capsys) -> None:
    _run(tmp_path, ["registry", "add", "--kind", "mcp", "--name", "fs",
                    "--path", str(FIXTURES / "mcp-clean.json"), "--source", "local"])
    assert _run(tmp_path, ["registry", "list"]) == 0
    assert "fs" in capsys.readouterr().out
    assert _run(tmp_path, ["registry", "list", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload[0]["name"] == "fs"
    assert _run(tmp_path, ["registry", "remove", "--kind", "mcp", "--name", "fs"]) == 0
    assert _run(tmp_path, ["registry", "remove", "--kind", "mcp", "--name", "fs"]) == 1


def test_scan_records_assets_events_and_stats(tmp_path: Path, capsys) -> None:
    _run(tmp_path, ["scan", str(FIXTURES / "evil-skill"), "--host", "d2-dev"])
    assert _run(tmp_path, ["assets", "--kind", "skill"]) == 0
    assert "evil-skill" in capsys.readouterr().out
    assert _run(tmp_path, ["events", "--severity", "critical"]) == 0
    assert "no events" in capsys.readouterr().out
    assert _run(tmp_path, ["stats", "--json"]) == 0
    stats = json.loads(capsys.readouterr().out)
    assert stats["events_total"] == 0
    assert stats["by_rule"] == {}
    assert stats["inventory_scan_verdicts"].get("block", 0) >= 1


def test_guard_capabilities_lists_tiers(tmp_path: Path, capsys) -> None:
    assert _run(tmp_path, ["guard", "capabilities"]) == 0
    out = capsys.readouterr().out
    assert "claude-code" in out and "codex" in out and "cursor" in out
    assert "[hook" in out and "[discovery" in out
    assert _run(tmp_path, ["guard", "capabilities", "--json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    tiers = {row["key"]: row["tier"] for row in rows}
    assert tiers["codex"] == "hook"
    assert tiers["workbuddy"] == "discovery"
    assert tiers["hermes"] == "discovery"
    assert tiers["opencode"] == "discovery"
    assert tiers["aider"] == "discovery"
    assert tiers["stepcode"] == "discovery"


def test_guard_install_rejects_discovery_tier(tmp_path: Path) -> None:
    assert _run(tmp_path, ["guard", "install", "--agent", "cursor"]) != 0


def test_hook_entry_point_accepts_agent_flag(tmp_path: Path, capsys) -> None:
    payload = json.dumps({"session_id": "s-cli", "tool_name": "Bash",
                          "tool_input": {"command": "rm -rf /home/u"}})
    import io
    import sys
    saved = sys.stdin
    sys.stdin = io.StringIO(payload)
    try:
        code = _run(tmp_path, ["hook", "pre-tool-use", "--agent", "codex"])
    finally:
        sys.stdin = saved
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
