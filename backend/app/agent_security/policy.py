from __future__ import annotations

import fnmatch
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .models import Decision, SecurityAction, Severity
from .rules import RULES_BY_ID, RUNTIME_RULES_BY_ID

# Runtime command rules reused from the shared 28-rule catalog so that the
# scanner and the runtime guard speak the same rule IDs.
_COMMAND_BLOCK_RULES = ("S04", "S05", "S07")
_COMMAND_ASK_RULES = ("S06", "S27")
_PATH_RULE_ID = "S08"

# V1 runtime rules (landing doc 11.2).
_SSH_KEY_RULE_ID = "R001"
_CLOUD_CRED_RULE_ID = "R002"
_NETWORK_TOOL_RULE_ID = "R003"
_UNAPPROVED_MCP_RULE_ID = "R004"

_PATH_KEYS = ("file_path", "path", "notebook_path", "filename", "directory", "target", "dest")
_COMMAND_KEYS = ("command", "cmd", "script", "shell")
_PATH_TOKEN_RE = re.compile(
    r"(~/[^\s\"']+|/(?:etc|usr|var|home|root|opt|tmp|Users|Library)/[^\s\"']+"
    r"|\.\.?/[^\s\"']+|[A-Za-z]:\\[^\s\"']+)"
)

DEFAULT_POLICIES: dict[str, Any] = {
    "version": 1,
    "block_paths": ["~/.ssh", "~/.aws", "~/.kube/config", "~/.gnupg",
                    "**/.env", "**/secrets.yaml", "**/secrets.json"],
    "ask_paths": ["/root", "~/.config"],
    "block_commands": [
        r"rm\s+-[a-z]*[rf][a-z]*\s+(/|~|\*|\$home)",
        r"(curl|wget)[^\n|]{0,200}\|\s*(sudo\s+)?(bash|sh|zsh)\b",
        r"/dev/tcp/",
        r"\bnc(at)?\s+(-[a-z]+\s+)*-e\b",
    ],
    "ask_commands": [r"\bsudo\b", r"\bgit\s+push\b", r"\bchmod\s+[0-7]*[4567][0-7]{3}"],
    "approved_network_tools": ["curl", "wget"],
    "approved_mcp_servers": ["filesystem", "fetch", "git", "sqlite", "memory", "time"],
    "prod_hosts": [],
}


@dataclass(frozen=True)
class CallerContext:
    host: str = ""
    host_role: str = ""
    user: str = ""
    session_id: str = ""
    agent_name: str = ""
    tool_server: str = ""
    cwd: str = ""


@dataclass(frozen=True)
class GuardPolicies:
    block_paths: tuple[str, ...] = ()
    ask_paths: tuple[str, ...] = ()
    block_commands: tuple[str, ...] = ()
    ask_commands: tuple[str, ...] = ()
    approved_network_tools: tuple[str, ...] = ()
    approved_mcp_servers: tuple[str, ...] = ()
    prod_hosts: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "GuardPolicies":
        return cls(
            block_paths=tuple(payload.get("block_paths", ())),
            ask_paths=tuple(payload.get("ask_paths", ())),
            block_commands=tuple(payload.get("block_commands", ())),
            ask_commands=tuple(payload.get("ask_commands", ())),
            approved_network_tools=tuple(payload.get("approved_network_tools", ())),
            approved_mcp_servers=tuple(payload.get("approved_mcp_servers", ())),
            prod_hosts=tuple(payload.get("prod_hosts", ())),
        )


def default_policies() -> GuardPolicies:
    return GuardPolicies.from_dict(DEFAULT_POLICIES)


def load_policies(path: str | Path | None) -> GuardPolicies:
    if not path:
        return default_policies()
    resolved = Path(path)
    if not resolved.exists():
        return default_policies()
    text = resolved.read_text(encoding="utf-8")
    if resolved.suffix in {".yaml", ".yml"}:
        try:
            import yaml  # type: ignore[import-untyped]

            payload = yaml.safe_load(text)
        except ImportError:
            payload = None
    else:
        payload = json.loads(text)
    if not isinstance(payload, dict):
        return default_policies()
    return GuardPolicies.from_dict(payload)


def normalize_path(raw: str, base: str = "") -> str:
    """Expand and canonicalize a path so symlink/traversal tricks cannot bypass.

    Relative paths resolve against ``base`` (the hook payload's ``cwd``, the
    directory the agent actually runs in), never against the guard process's
    own cwd, which is unrelated on edge installs.
    """
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute() and base:
        candidate = Path(base).expanduser() / candidate
    try:
        return str(candidate.resolve())
    except (OSError, RuntimeError, ValueError):
        return os.path.normpath(os.path.abspath(str(candidate)))


def _expand_pattern(pattern: str) -> str:
    return normalize_path(pattern) if pattern.startswith(("~", "/", ".")) else pattern


def path_matches(path: str, pattern: str) -> bool:
    expanded = _expand_pattern(pattern)
    if path == expanded or path.startswith(expanded + os.sep):
        return True
    if pattern.startswith("~/"):
        # A ~/ pattern must also cover the same directory under other users.
        if fnmatch.fnmatch(path, "/*" + pattern[1:]):
            return True
    return fnmatch.fnmatch(path, expanded) or fnmatch.fnmatch(path, expanded + "/*")


def matches_catalog_sensitive_path(path: str) -> bool:
    return bool(classify_sensitive_path(path))


def classify_sensitive_path(path: str) -> list[str]:
    """Map a normalized path onto the sensitive-path rules it triggers.

    SSH private keys attribute to R001 and cloud credentials to R002 (the
    first-version runtime rules); every catalog sensitive path also carries
    the generic S08 rule so the static and runtime layers stay aligned.
    """
    rule_ids: list[str] = []
    for rule_id in (_SSH_KEY_RULE_ID, _CLOUD_CRED_RULE_ID, _PATH_RULE_ID):
        rule = RUNTIME_RULES_BY_ID.get(rule_id) or RULES_BY_ID.get(rule_id)
        if rule and rule.pattern and re.search(rule.pattern, path):
            rule_ids.append(rule_id)
    return rule_ids


def extract_tool_server(tool_name: str) -> str:
    """Derive the MCP server name from an agent tool name.

    Claude Code exposes MCP tools as ``mcp__<server>__<tool>``; the server
    segment is what the approved-MCP whitelist (rule R004) is matched on.
    """
    parts = str(tool_name or "").split("__")
    if len(parts) >= 3 and parts[0] == "mcp":
        return parts[1]
    return ""


def extract_paths(tool_input: dict[str, Any], cwd: str = "") -> list[str]:
    paths: list[str] = []
    for key in _PATH_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str) and value:
            paths.append(normalize_path(value, cwd))
    for key in _COMMAND_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str):
            paths.extend(normalize_path(token, cwd)
                         for token in _PATH_TOKEN_RE.findall(value))
    return [path for path in paths if path]


def extract_commands(tool_input: dict[str, Any]) -> list[str]:
    commands: list[str] = []
    for key in _COMMAND_KEYS:
        value = tool_input.get(key)
        if isinstance(value, str) and value.strip():
            commands.append(value)
        elif isinstance(value, list):
            commands.extend(str(item) for item in value if isinstance(item, str))
    return commands


def _host_matches(host: str, patterns: tuple[str, ...]) -> bool:
    return any(fnmatch.fnmatch(host, pattern) for pattern in patterns)


def _severity_for(action: SecurityAction) -> Severity:
    if action == SecurityAction.BLOCK:
        return Severity.HIGH
    if action == SecurityAction.ASK:
        return Severity.MEDIUM
    return Severity.INFO


def decide(
    tool_name: str,
    tool_input: dict[str, Any],
    ctx: CallerContext,
    policies: GuardPolicies,
) -> Decision:
    """Pure policy decision. Any internal failure fails closed to block."""
    try:
        return _decide(tool_name, tool_input, ctx, policies)
    except Exception as exc:  # fail-closed by design (landing doc 4.6)
        return Decision(
            action=SecurityAction.BLOCK,
            rule_ids=[],
            matched_signals=["policy_engine_error"],
            reason=f"policy engine error, failing closed: {exc}",
        )


def _decide(
    tool_name: str,
    tool_input: dict[str, Any],
    ctx: CallerContext,
    policies: GuardPolicies,
) -> Decision:
    tool_input = tool_input if isinstance(tool_input, dict) else {}
    signals: list[str] = []
    rule_ids: list[str] = []
    action = SecurityAction.ALLOW
    reason = "no policy match"

    for path in extract_paths(tool_input, ctx.cwd):
        sensitive_rules = classify_sensitive_path(path)
        if sensitive_rules:
            signals.append("catalog_sensitive_path")
            for rule_id in sensitive_rules:
                if rule_id not in rule_ids:
                    rule_ids.append(rule_id)
            action = SecurityAction.BLOCK
            reason = f"path matches sensitive-path rules {','.join(sensitive_rules)}: {path}"
        for pattern in policies.block_paths:
            if path_matches(path, pattern):
                signals.append(f"blocked_path:{pattern}")
                if _PATH_RULE_ID not in rule_ids:
                    rule_ids.append(_PATH_RULE_ID)
                action = SecurityAction.BLOCK
                reason = f"path matches block_paths pattern '{pattern}': {path}"
        for pattern in policies.ask_paths:
            if path_matches(path, pattern):
                signals.append(f"ask_path:{pattern}")
                if action != SecurityAction.BLOCK:
                    action = SecurityAction.ASK
                    reason = f"path matches ask_paths pattern '{pattern}': {path}"

    network_rule = RUNTIME_RULES_BY_ID.get(_NETWORK_TOOL_RULE_ID)
    for command in extract_commands(tool_input):
        first_token = command.strip().split()[0].rsplit("/", 1)[-1] if command.strip() else ""
        if (network_rule and network_rule.pattern
                and re.search(network_rule.pattern, command)
                and first_token not in policies.approved_network_tools):
            signals.append(f"unapproved_network_tool:{first_token}")
            if _NETWORK_TOOL_RULE_ID not in rule_ids:
                rule_ids.append(_NETWORK_TOOL_RULE_ID)
            if action != SecurityAction.BLOCK:
                action = SecurityAction.ASK
                reason = f"network tool '{first_token}' is not in approved_network_tools"
        for rule_id in _COMMAND_BLOCK_RULES:
            rule = RULES_BY_ID.get(rule_id)
            if rule and rule.pattern and re.search(rule.pattern, command):
                signals.append(f"command_rule:{rule_id}")
                if rule_id not in rule_ids:
                    rule_ids.append(rule_id)
                action = SecurityAction.BLOCK
                reason = f"command matches blocking rule {rule_id}"
        for rule_id in _COMMAND_ASK_RULES:
            rule = RULES_BY_ID.get(rule_id)
            if rule and rule.pattern and re.search(rule.pattern, command):
                signals.append(f"command_rule:{rule_id}")
                if rule_id not in rule_ids:
                    rule_ids.append(rule_id)
                if action != SecurityAction.BLOCK:
                    action = SecurityAction.ASK
                    reason = f"command matches ask rule {rule_id}"
        for pattern in policies.block_commands:
            if re.search(pattern, command):
                signals.append(f"blocked_command:{pattern[:40]}")
                action = SecurityAction.BLOCK
                reason = f"command matches block_commands pattern '{pattern[:40]}'"
        for pattern in policies.ask_commands:
            if re.search(pattern, command):
                signals.append(f"ask_command:{pattern[:40]}")
                if action != SecurityAction.BLOCK:
                    action = SecurityAction.ASK
                    reason = f"command matches ask_commands pattern '{pattern[:40]}'"

    tool_server = ctx.tool_server or extract_tool_server(tool_name)
    if tool_server and tool_server not in policies.approved_mcp_servers:
        signals.append(f"unapproved_mcp_server:{tool_server}")
        if _UNAPPROVED_MCP_RULE_ID not in rule_ids:
            rule_ids.append(_UNAPPROVED_MCP_RULE_ID)
        action = SecurityAction.BLOCK
        reason = f"MCP server '{tool_server}' is not in the approved whitelist"

    if ctx.host and _host_matches(ctx.host, policies.prod_hosts):
        signals.append("prod_host")
        if action == SecurityAction.ASK:
            action = SecurityAction.BLOCK
            reason = "ask upgraded to block on production host"
        elif action == SecurityAction.ALLOW:
            action = SecurityAction.AUDIT
            reason = "agent session on production host"

    return Decision(
        action=action,
        rule_ids=rule_ids,
        matched_signals=signals,
        reason=reason,
    )
