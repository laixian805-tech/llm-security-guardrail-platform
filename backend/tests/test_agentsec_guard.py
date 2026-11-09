from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from app.agent_security.cli import main
from app.agent_security.guard import (
    HOOK_SPECS,
    guard_status,
    install_guard,
    uninstall_guard,
)

ALL_EVENTS = sorted(HOOK_SPECS)


@pytest.fixture(autouse=True)
def _isolate_home(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("AGENTSEC_HOME", str(tmp_path / "agentsec-home"))
    monkeypatch.setenv("AGENTSEC_DB_PATH", str(tmp_path / "agentsec.db"))
    monkeypatch.delenv("AGENTSEC_POLICIES", raising=False)


def _settings(tmp_path: Path) -> Path:
    return tmp_path / "home" / ".claude" / "settings.json"


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _agentsec_entries(payload: dict) -> list[dict]:
    entries = []
    for event_entries in payload.get("hooks", {}).values():
        entries.extend(e for e in event_entries if isinstance(e, dict))
    return [e for e in entries
            if any("-m app.agent_security hook " in str(h.get("command", ""))
                   for h in e.get("hooks", []) if isinstance(h, dict))]


def test_install_creates_hooks_for_all_events(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    result = install_guard(settings_path=settings)
    assert sorted(result.installed) == ALL_EVENTS
    payload = _read(settings)
    assert sorted(payload["hooks"]) == ALL_EVENTS
    for event, matcher in HOOK_SPECS.items():
        entry = payload["hooks"][event][0]
        assert entry["matcher"] == matcher
        command = entry["hooks"][0]["command"]
        assert "-m app.agent_security hook " in command
        assert command.startswith('"')  # absolute interpreter, quoted
    # state dir, policies defaults and baseline are created
    state = tmp_path / "agentsec-home"
    assert (state / "hooks").is_dir()
    assert (state / "policies.json").is_file()
    assert (state / "hook-baseline.json").is_file()
    policies = _read(state / "policies.json")
    assert policies["block_paths"]


def test_install_is_idempotent(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    install_guard(settings_path=settings)
    first = _read(settings)
    second = install_guard(settings_path=settings)
    assert second.installed == []
    assert sorted(second.already_present) == ALL_EVENTS
    assert _read(settings) == first  # no duplicate entries
    assert len(_agentsec_entries(first)) == len(ALL_EVENTS)


def test_install_preserves_existing_keys_and_user_hooks(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    settings.parent.mkdir(parents=True)
    settings.write_text(json.dumps({
        "model": "opus",
        "hooks": {"PreToolUse": [
            {"matcher": "Bash",
             "hooks": [{"type": "command", "command": "/usr/local/bin/my-audit"}]},
        ]},
    }), encoding="utf-8")
    install_guard(settings_path=settings)
    payload = _read(settings)
    assert payload["model"] == "opus"
    pre_entries = payload["hooks"]["PreToolUse"]
    assert len(pre_entries) == 2  # user entry kept, agentsec entry appended
    user_commands = [h["command"] for h in pre_entries[0]["hooks"]]
    assert user_commands == ["/usr/local/bin/my-audit"]
    agentsec_commands = [h["command"] for h in pre_entries[1]["hooks"]]
    assert any("-m app.agent_security hook " in c for c in agentsec_commands)


def test_install_backs_up_existing_settings(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    settings.parent.mkdir(parents=True)
    original = {"model": "sonnet"}
    settings.write_text(json.dumps(original), encoding="utf-8")
    result = install_guard(settings_path=settings)
    assert result.backup_path is not None
    assert result.backup_path.exists()
    assert _read(result.backup_path) == original


def test_uninstall_removes_only_agentsec_hooks(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    settings.parent.mkdir(parents=True)
    settings.write_text(json.dumps({
        "model": "opus",
        "hooks": {"PreToolUse": [
            {"matcher": "Bash",
             "hooks": [{"type": "command", "command": "/usr/local/bin/my-audit"}]},
        ]},
    }), encoding="utf-8")
    install_guard(settings_path=settings)
    result = uninstall_guard(settings_path=settings)
    assert sorted(result.removed) == ALL_EVENTS
    assert result.backup_path is not None and result.backup_path.exists()
    payload = _read(settings)
    assert payload["model"] == "opus"
    # user hook entry survives untouched, agentsec entries are gone
    assert len(payload["hooks"]["PreToolUse"]) == 1
    assert payload["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == \
        "/usr/local/bin/my-audit"
    assert _agentsec_entries(payload) == []


def test_uninstall_removes_empty_hooks_section(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    install_guard(settings_path=settings)
    uninstall_guard(settings_path=settings)
    payload = _read(settings)
    assert "hooks" not in payload or payload["hooks"] == {}


def test_uninstall_without_install_is_noop(tmp_path: Path) -> None:
    result = uninstall_guard(settings_path=_settings(tmp_path))
    assert result.removed == []
    assert result.backup_path is None


def test_status_reports_installed_events_and_baseline(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    status = guard_status(settings_path=settings)
    assert status["installed_events"] == []
    assert status["baseline_match"] is False
    install_guard(settings_path=settings)
    status = guard_status(settings_path=settings)
    assert status["installed_events"] == ALL_EVENTS
    assert status["baseline_match"] is True
    assert status["policies_loaded"] is True
    assert status["block_paths"]


def test_status_detects_settings_tamper(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    install_guard(settings_path=settings)
    assert guard_status(settings_path=settings)["baseline_match"] is True
    payload = _read(settings)
    payload["extra_key"] = "injected"
    settings.write_text(json.dumps(payload), encoding="utf-8")
    status = guard_status(settings_path=settings)
    assert status["baseline_match"] is False
    assert status["installed_events"] == ALL_EVENTS


def test_status_survives_corrupt_settings(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    settings.parent.mkdir(parents=True)
    settings.write_text("{not json", encoding="utf-8")
    status = guard_status(settings_path=settings)
    assert status["installed_events"] == []
    assert status["baseline_match"] is False


def test_discovery_tier_agent_refuses_hook_install() -> None:
    """Discovery-tier products are managed by scan+monitor, never by hooks."""
    with pytest.raises(ValueError, match="discovery-only"):
        install_guard("cursor")
    with pytest.raises(ValueError, match="discovery-only"):
        uninstall_guard("cursor")


def test_unknown_agent_raises() -> None:
    with pytest.raises(ValueError):
        install_guard("not-a-product")
    with pytest.raises(ValueError):
        uninstall_guard("not-a-product")
    with pytest.raises(ValueError):
        guard_status("not-a-product")


def test_install_codex_uses_regex_matcher_with_mcp(tmp_path: Path) -> None:
    """Codex matcher is a regex; MCP tools are mcp__<server>__<tool>."""
    settings = tmp_path / "home" / ".codex" / "hooks.json"
    result = install_guard("codex", settings_path=settings)
    assert sorted(result.installed) == ALL_EVENTS
    payload = _read(settings)
    pre = payload["hooks"]["PreToolUse"][0]
    assert "mcp__.*" in pre["matcher"]
    assert "apply_patch" in pre["matcher"]
    command = pre["hooks"][0]["command"]
    assert "--agent codex" in command


def test_install_pins_callback_in_baseline(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    install_guard(settings_path=settings)
    baseline = _read(tmp_path / "agentsec-home" / "hook-baseline.json")
    callbacks = baseline["callbacks"]
    assert "app.agent_security" in callbacks
    record = callbacks["app.agent_security"]
    assert record["kind"] == "module"
    assert Path(record["path"]).is_dir()
    assert record["sha256"]


def test_status_detects_callback_package_tamper(tmp_path: Path,
                                                monkeypatch) -> None:
    """S21/S22 backstop: the callback package itself is hash-pinned."""
    settings = _settings(tmp_path)
    install_guard(settings_path=settings)
    baseline_path = tmp_path / "agentsec-home" / "hook-baseline.json"
    baseline = _read(baseline_path)
    baseline["package_sha256"] = "0" * 64
    baseline["callbacks"]["app.agent_security"]["sha256"] = "1" * 64
    baseline_path.write_text(json.dumps(baseline), encoding="utf-8")
    status = guard_status(settings_path=settings)
    assert status["baseline_match"] is False
    assert status["package_match"] is False
    assert status["callbacks_match"] is False
    assert status["callbacks"]["app.agent_security"]["match"] is False


def test_status_reports_governance_and_trust(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    codex_home = tmp_path / "home" / ".codex"
    codex_home.mkdir(parents=True)
    (codex_home / "config.toml").write_text(
        'sandbox_mode = "danger-full-access"\napproval_policy = "never"\n',
        encoding="utf-8")
    status = guard_status("codex", settings_path=codex_home / "hooks.json")
    risks = {risk["key"]: risk["value"]
             for risk in status["governance"]["risks"]}
    assert risks["sandbox_mode"] == "danger-full-access"
    assert risks["approval_policy"] == "never"
    assert status["trust_hash_pinned"] is True
    assert status["trust_verified"] is False


def test_status_discovery_tier_reports_coverage(tmp_path: Path) -> None:
    status = guard_status("cursor", settings_path=tmp_path / "nope.json")
    assert status["tier"] == "discovery"
    assert status["discovery_only"] is True
    assert status["installed_events"] == []


def test_capabilities_matrix_covers_all_products() -> None:
    from app.agent_security.adapters import capability_matrix
    rows = {row["key"]: row for row in capability_matrix()}
    assert {"claude-code", "codex", "cursor", "windsurf", "gemini-cli",
            "qwen", "openclaw", "hermes", "opencode", "aider",
            "stepcode", "workbuddy", "qcode"} <= set(rows)
    for key in ("claude-code", "codex"):
        assert rows[key]["tier"] == "hook"
        assert rows[key]["events"]
    for key in ("cursor", "windsurf", "gemini-cli", "qwen", "openclaw",
                "hermes", "opencode", "aider", "stepcode", "workbuddy", "qcode"):
        assert rows[key]["tier"] == "discovery"
        assert rows[key]["events"] == {}
        assert rows[key]["process_comms"]


def test_guard_cli_roundtrip(tmp_path: Path, capsys) -> None:
    settings = _settings(tmp_path)
    assert main(["guard", "install", "--settings", str(settings)]) == 0
    out = capsys.readouterr().out
    assert "PreToolUse" in out and "SessionEnd" in out
    assert main(["guard", "status", "--settings", str(settings), "--json"]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["installed_events"] == ALL_EVENTS
    assert status["baseline_match"] is True
    assert main(["guard", "uninstall", "--settings", str(settings)]) == 0
    assert "PreToolUse" in capsys.readouterr().out
    assert main(["guard", "status", "--settings", str(settings), "--json"]) == 0
    status = json.loads(capsys.readouterr().out)
    assert status["installed_events"] == []
