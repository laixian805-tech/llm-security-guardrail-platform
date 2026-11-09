from __future__ import annotations

import importlib.util
import json
import shutil
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .adapters import (HOOK_TIER, AgentAdapter, get_adapter, hook_command,
                       read_governance)
from .hook import audit_failure_count
from .paths import agentsec_dir
from .policy import DEFAULT_POLICIES, load_policies
from .scanner import dir_digest


def hooks_dir() -> Path:
    return agentsec_dir() / "hooks"


def policies_file() -> Path:
    return agentsec_dir() / "policies.json"


def baseline_file() -> Path:
    return agentsec_dir() / "hook-baseline.json"


def hook_specs(agent: str = "claude-code") -> dict[str, str]:
    """Product hook event -> matcher, from the product's capability matrix."""
    return dict(get_adapter(agent).matchers)


# Default (claude-code) view, kept for backwards compatibility.
HOOK_SPECS: dict[str, str] = hook_specs()

# Our subcommand names per product event (claude-code view, for compatibility).
EVENT_SUBCOMMANDS: dict[str, str] = {
    event: subcommand
    for subcommand, event in get_adapter("claude-code").events.items()
}


@dataclass
class InstallResult:
    settings_path: Path
    backup_path: Path | None
    installed: list[str] = field(default_factory=list)
    already_present: list[str] = field(default_factory=list)
    policies_path: Path = field(default_factory=policies_file)
    baseline_path: Path = field(default_factory=baseline_file)


@dataclass
class UninstallResult:
    settings_path: Path
    removed: list[str] = field(default_factory=list)
    backup_path: Path | None = None


def default_settings_path(agent: str = "claude-code") -> Path:
    adapter = get_adapter(agent)
    if not adapter.settings_relpath:
        raise ValueError(f"{agent} ({adapter.display_name}) has no known "
                         f"settings file; coverage is process discovery only")
    return Path.home().joinpath(*adapter.settings_relpath)


def _require_hook_tier(agent: str) -> AgentAdapter:
    adapter = get_adapter(agent)
    if adapter.tier != HOOK_TIER:
        raise ValueError(
            f"{agent} ({adapter.display_name}) is discovery-only: no confirmed "
            f"hook protocol, so no blocking hooks are installed. Cover it with "
            f"`agentsec scan` plus the behavior monitor instead.")
    return adapter


def _hook_command(interpreter: str, module: str, adapter: AgentAdapter,
                  event: str) -> str:
    return hook_command(interpreter, module, adapter,
                        adapter.subcommand_for_event(event))


def _our_command(command: str, module: str) -> bool:
    return f"-m {module} hook " in command


def install_guard(
    agent: str = "claude-code",
    *,
    settings_path: str | Path | None = None,
    module: str = "app.agent_security",
    interpreter: str | None = None,
) -> InstallResult:
    """Merge agentsec hooks into the agent settings file.

    Backs up first, merges instead of overwrites, and is idempotent: entries
    whose command already points at this module are left untouched. Only
    hook-tier products may be installed; discovery-tier products are covered
    by scanning and monitoring instead.
    """
    adapter = _require_hook_tier(agent)
    interpreter = interpreter or sys.executable
    target = Path(settings_path) if settings_path else default_settings_path(agent)
    result = InstallResult(settings_path=target, backup_path=None)

    payload: dict[str, Any] = {}
    if target.exists():
        payload = json.loads(target.read_text(encoding="utf-8"))
        result.backup_path = _backup(target)
    if not isinstance(payload, dict):
        payload = {}

    hooks = payload.setdefault("hooks", {})
    for event, matcher in hook_specs(agent).items():
        command = _hook_command(interpreter, module, adapter, event)
        entries = hooks.setdefault(event, [])
        if not isinstance(entries, list):
            entries = []
            hooks[event] = entries
        existing = [
            entry for entry in entries
            if isinstance(entry, dict) and isinstance(entry.get("hooks"), list)
            and any(isinstance(h, dict) and _our_command(str(h.get("command", "")), module)
                    for h in entry["hooks"])
        ]
        if existing:
            result.already_present.append(event)
            continue
        entries.append({
            "matcher": matcher,
            "hooks": [{"type": "command", "command": command, "timeout": 10}],
        })
        result.installed.append(event)

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
                      encoding="utf-8")

    state_dir = agentsec_dir()
    state_dir.mkdir(parents=True, exist_ok=True)
    hooks_dir().mkdir(parents=True, exist_ok=True)
    result.policies_path = policies_file()
    result.baseline_path = baseline_file()
    if not result.policies_path.exists():
        result.policies_path.write_text(
            json.dumps(DEFAULT_POLICIES, ensure_ascii=False, indent=2),
            encoding="utf-8")
    _write_baseline(adapter, target, module)
    return result


def uninstall_guard(
    agent: str = "claude-code",
    *,
    settings_path: str | Path | None = None,
    module: str = "app.agent_security",
) -> UninstallResult:
    adapter = _require_hook_tier(agent)
    target = Path(settings_path) if settings_path else default_settings_path(agent)
    result = UninstallResult(settings_path=target)
    if not target.exists():
        return result
    payload = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return result
    hooks = payload.get("hooks")
    if not isinstance(hooks, dict):
        return result
    result.backup_path = _backup(target)
    for event, entries in list(hooks.items()):
        if not isinstance(entries, list):
            continue
        kept: list[Any] = []
        for entry in entries:
            if not isinstance(entry, dict) or not isinstance(entry.get("hooks"), list):
                kept.append(entry)
                continue
            inner = [
                h for h in entry["hooks"]
                if not (isinstance(h, dict) and _our_command(str(h.get("command", "")), module))
            ]
            if inner:
                entry["hooks"] = inner
                kept.append(entry)
            else:
                result.removed.append(event)
        if kept:
            hooks[event] = kept
        else:
            hooks.pop(event, None)
    if not hooks:
        payload.pop("hooks", None)
    target.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return result


def guard_status(
    agent: str = "claude-code",
    *,
    settings_path: str | Path | None = None,
    module: str = "app.agent_security",
) -> dict[str, Any]:
    adapter = get_adapter(agent)
    target: Path | None = None
    if settings_path:
        target = Path(settings_path)
    elif adapter.settings_relpath:
        target = Path.home().joinpath(*adapter.settings_relpath)
    installed_events: list[str] = []
    if target is not None and target.exists():
        try:
            payload = json.loads(target.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            payload = {}
        hooks = payload.get("hooks") if isinstance(payload, dict) else {}
        if isinstance(hooks, dict):
            for event, entries in hooks.items():
                if isinstance(entries, list) and any(
                    isinstance(entry, dict) and isinstance(entry.get("hooks"), list)
                    and any(isinstance(h, dict)
                            and _our_command(str(h.get("command", "")), module)
                            for h in entry["hooks"])
                    for entry in entries
                ):
                    installed_events.append(event)
    baseline = _read_baseline()
    settings_digest = _file_digest(target) if target is not None else ""
    settings_match = bool(baseline) and bool(target is not None) \
        and baseline.get("settings_sha256") == settings_digest
    package_digest = dir_digest(Path(__file__).resolve().parent)
    package_match = bool(baseline) and baseline.get("package_sha256") == package_digest
    callbacks, callbacks_match = _callback_status(baseline)
    policies = load_policies(policies_file())
    status: dict[str, Any] = {
        "agent": adapter.key,
        "agent_name": adapter.agent_name,
        "tier": adapter.tier,
        "settings_path": str(target) if target is not None else "",
        "installed_events": sorted(installed_events),
        "baseline_match": settings_match and package_match,
        "settings_match": settings_match,
        "package_match": package_match,
        "callbacks": callbacks,
        "callbacks_match": callbacks_match,
        "policies_path": str(policies_file()),
        "policies_loaded": True,
        "block_paths": list(policies.block_paths),
        "trust": list(adapter.trust),
        "trust_hash_pinned": adapter.trust_hash_pinned,
        "trust_verified": False,
        "governance": read_governance(adapter),
        "audit_failures": audit_failure_count(),
    }
    if adapter.tier != HOOK_TIER:
        status["discovery_only"] = True
        status["note"] = ("discovery-tier product: no hook protocol is installed; "
                          "coverage comes from process discovery and config scanning")
    return status


def _callback_status(baseline: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Re-digest every baseline-pinned hook callback and report per-entry match."""
    entries = baseline.get("callbacks")
    if not isinstance(entries, dict) or not entries:
        return {}, False
    callbacks: dict[str, Any] = {}
    matched = True
    for identity, record in entries.items():
        if not isinstance(record, dict):
            matched = False
            continue
        root = Path(str(record.get("path", "")))
        expected = str(record.get("sha256", ""))
        current = dir_digest(root) if root.is_dir() else ""
        ok = bool(expected) and current == expected
        callbacks[identity] = {"path": str(root), "match": ok,
                               "kind": record.get("kind", "")}
        matched = matched and ok
    return callbacks, matched


def _backup(target: Path) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    backup = target.with_name(f"{target.name}.agentsec-bak-{stamp}")
    shutil.copy2(target, backup)
    return backup


def _file_digest(path: Path) -> str:
    import hashlib

    if not path.exists():
        return ""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _module_package_dir(module: str) -> Path | None:
    try:
        spec = importlib.util.find_spec(module)
    except (ImportError, ValueError):
        return None
    if spec is None or not spec.origin:
        return None
    return Path(spec.origin).resolve().parent


def _write_baseline(adapter: AgentAdapter, settings_path: Path, module: str) -> None:
    """Pin the settings file and every hook callback the install wrote.

    The scanner's S22 rule re-digests these entries: a replaced callback
    script/module must alert even when settings.json itself is untouched.
    """
    agentsec_dir().mkdir(parents=True, exist_ok=True)
    package_dir = Path(__file__).resolve().parent
    callbacks: dict[str, Any] = {}
    module_dir = _module_package_dir(module)
    if module_dir is not None and module_dir.is_dir():
        callbacks[module] = {"kind": "module", "path": str(module_dir),
                             "sha256": dir_digest(module_dir)}
    baseline = {
        "agent": adapter.key,
        "settings_path": str(settings_path),
        "settings_sha256": _file_digest(settings_path),
        "package_sha256": dir_digest(package_dir),
        "module": module,
        "callbacks": callbacks,
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    baseline_file().write_text(json.dumps(baseline, ensure_ascii=False, indent=2),
                               encoding="utf-8")


def _read_baseline() -> dict[str, Any]:
    target = baseline_file()
    if not target.exists():
        return {}
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}
    return payload if isinstance(payload, dict) else {}
