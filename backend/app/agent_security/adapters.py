"""Per-product capability matrix and hook-protocol translation.

The guard core (``policy.decide``) only ever produces a product-neutral
``Decision``. Everything that differs between Agent products lives here:
config file location, hook event names, matcher syntax, payload field
names, the deny/ask output protocol, the trust model, and the sandbox /
approval knobs that governance must audit (landing doc 4.4, 7.4 of the
research notes).

Two tiers:

* ``hook`` tier — the product's hook protocol is confirmed against the
  installed version. ``guard install`` may write blocking hooks for it.
* ``discovery`` tier — no confirmed hook protocol (or none at all). The
  platform still manages the product through process discovery (monitor)
  and config scanning (scanner); ``guard install`` refuses instead of
  writing a config the product might silently ignore.

Codex facts below were verified against the installed Codex CLI 0.166.0
binary (embedded JSON schemas and config strings): PreToolUse input uses
``session_id/cwd/hook_event_name/tool_name/tool_input/tool_use_id/
permission_mode``; the command output protocol is
``{"hookSpecificOutput": {"hookEventName": "PreToolUse",
"permissionDecision": "allow|deny|ask", "permissionDecisionReason": ...}}``;
non-managed hooks must be reviewed and trusted (``/hooks review``) and the
definition is hash-pinned (``trusted_hash``/``currentHash``), so a changed
definition is skipped until re-reviewed; ``--dangerously-bypass-hook-trust``
bypasses the gate; enterprise managed hooks are enforced through
``allow_managed_hooks_only``.
"""

from __future__ import annotations

import json
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 edge hosts use the tomli backport.
    import tomli as tomllib  # type: ignore[no-redef]
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import SecurityAction

EXIT_ALLOW = 0
EXIT_BLOCK = 2

DEFAULT_AGENT = "claude-code"

HOOK_TIER = "hook"
DISCOVERY_TIER = "discovery"


@dataclass(frozen=True)
class GovernanceCheck:
    """One sandbox/approval knob to read from the product's own config."""

    key: str
    kind: str                     # "enum" | "bool"
    risky_values: tuple[Any, ...]
    risk: str


@dataclass(frozen=True)
class AgentAdapter:
    key: str
    display_name: str
    tier: str                                   # hook | discovery
    agent_name: str                             # injected into events/CallerContext
    settings_relpath: tuple[str, ...] = ()      # product config, relative to $HOME
    events: dict[str, str] = field(default_factory=dict)    # our subcommand -> product event key
    matchers: dict[str, str] = field(default_factory=dict)  # product event key -> matcher
    deny_via: str = ""                          # "exit-2" | "json"
    input_keys: dict[str, str] = field(default_factory=dict)
    trust: tuple[str, ...] = ()
    trust_hash_pinned: bool = False
    process_comms: tuple[str, ...] = ()
    scan_paths: tuple[tuple[str, ...], ...] = ()
    governance_file: tuple[str, ...] = ()
    governance_checks: tuple[GovernanceCheck, ...] = ()
    managed_settings_paths: tuple[tuple[str, ...], ...] = ()
    notes: str = ""

    def subcommand_for_event(self, product_event: str) -> str:
        for subcommand, event in self.events.items():
            if event == product_event:
                return subcommand
        raise KeyError(product_event)

    @property
    def pre_tool_event(self) -> str:
        return self.events.get("pre-tool-use", "PreToolUse")


_CLAUDE_INPUT_KEYS = {
    "session_id": "session_id",
    "cwd": "cwd",
    "tool_name": "tool_name",
    "tool_input": "tool_input",
    "permission_mode": "permission_mode",
}

_CODEX_INPUT_KEYS = dict(_CLAUDE_INPUT_KEYS)

_CODEX_TRUST = (
    "非托管 hooks 必须先 /hooks review 并信任后才会执行；"
    "guard status 只能证明配置条目存在，不能证明已被信任生效",
    "hook 定义按内容 hash 固定（trusted_hash/currentHash）：定义变更后会被跳过，需重新 review",
    "--dangerously-bypass-hook-trust 可绕过信任门，属高风险操作，应纳入审计",
    "企业可通过 managed hooks + allow_managed_hooks_only 只允许托管 hook 执行",
)

ADAPTERS: dict[str, AgentAdapter] = {
    "claude-code": AgentAdapter(
        key="claude-code",
        display_name="Claude Code",
        tier=HOOK_TIER,
        agent_name="claude-code",
        settings_relpath=(".claude", "settings.json"),
        events={
            "pre-tool-use": "PreToolUse",
            "post-tool-use": "PostToolUse",
            "session-start": "SessionStart",
            "session-end": "SessionEnd",
        },
        matchers={
            "PreToolUse": "Write|Edit|Read|Bash|MultiEdit|NotebookEdit|mcp__.*",
            "PostToolUse": "*",
            "SessionStart": "*",
            "SessionEnd": "*",
        },
        deny_via="exit-2",
        input_keys=_CLAUDE_INPUT_KEYS,
        trust=("settings.json 属主可改；企业应以 managed settings 统一下发并锁定",),
        trust_hash_pinned=False,
        process_comms=("claude", "claude-code"),
        scan_paths=((".claude", "settings.json"), (".claude", "settings.local.json")),
        governance_file=(".claude", "settings.json"),
        governance_checks=(),
        managed_settings_paths=(("etc", "claude-code", "managed-settings.json"),),
        notes="PreToolUse 阻断走 exit 2 + stderr（官方文档路径）；ask 走 hookSpecificOutput JSON。",
    ),
    "codex": AgentAdapter(
        key="codex",
        display_name="Codex CLI",
        tier=HOOK_TIER,
        agent_name="codex",
        settings_relpath=(".codex", "hooks.json"),
        events={
            "pre-tool-use": "PreToolUse",
            "post-tool-use": "PostToolUse",
            "session-start": "SessionStart",
            "session-end": "SessionEnd",
        },
        matchers={
            # Codex matcher is a regex over the tool name; MCP tools are
            # mcp__<server>__<tool>, so they must be matched explicitly.
            "PreToolUse": "Bash|apply_patch|mcp__.*",
            "PostToolUse": "*",
            "SessionStart": "*",
            "SessionEnd": "*",
        },
        deny_via="json",
        input_keys=_CODEX_INPUT_KEYS,
        trust=_CODEX_TRUST,
        trust_hash_pinned=True,
        process_comms=("codex", "codex-cli"),
        scan_paths=((".codex", "hooks.json"), (".codex", "config.toml")),
        governance_file=(".codex", "config.toml"),
        governance_checks=(
            GovernanceCheck("sandbox_mode", "enum", ("danger-full-access",),
                            "sandbox 被完全禁用：Agent 可读写整个文件系统"),
            GovernanceCheck("approval_policy", "enum", ("never",),
                            "审批被关闭：高危操作不再人工确认"),
            GovernanceCheck("allow_managed_hooks_only", "bool", (False,),
                            "未强制 managed hooks：用户级 hooks.json 仍可执行"),
        ),
        notes="deny/ask 均走 hookSpecificOutput JSON（0.166.0 内嵌 schema 验证）；"
              "hooks.json 事件键与 wire 事件名一致（PascalCase）。",
    ),
    "cursor": AgentAdapter(
        key="cursor",
        display_name="Cursor",
        tier=DISCOVERY_TIER,
        agent_name="cursor",
        settings_relpath=(".cursor", "mcp.json"),
        process_comms=("cursor", "cursor-agent"),
        scan_paths=((".cursor", "mcp.json"),),
        notes="未确认可用的 hook 协议：仅进程发现 + 配置扫描，不安装阻断 hook。",
    ),
    "windsurf": AgentAdapter(
        key="windsurf",
        display_name="Windsurf",
        tier=DISCOVERY_TIER,
        agent_name="windsurf",
        settings_relpath=(".codeium", "windsurf", "mcp_config.json"),
        process_comms=("windsurf",),
        scan_paths=((".codeium", "windsurf", "mcp_config.json"),),
        notes="未确认可用的 hook 协议：仅进程发现 + 配置扫描，不安装阻断 hook。",
    ),
    "gemini-cli": AgentAdapter(
        key="gemini-cli",
        display_name="Gemini CLI",
        tier=DISCOVERY_TIER,
        agent_name="gemini-cli",
        settings_relpath=(".gemini", "settings.json"),
        process_comms=("gemini",),
        scan_paths=((".gemini", "settings.json"),),
        notes="未确认可用的 hook 协议：仅进程发现 + 配置扫描，不安装阻断 hook。",
    ),
    "qwen": AgentAdapter(
        key="qwen",
        display_name="Qwen Code",
        tier=DISCOVERY_TIER,
        agent_name="qwen",
        settings_relpath=(".qwen", "settings.json"),
        process_comms=("qwen",),
        scan_paths=((".qwen", "settings.json"),),
        notes="未确认可用的 hook 协议：仅进程发现 + 配置扫描，不安装阻断 hook。",
    ),
    "openclaw": AgentAdapter(
        key="openclaw",
        display_name="OpenClaw",
        tier=DISCOVERY_TIER,
        agent_name="openclaw",
        process_comms=("openclaw",),
        notes="未确认可用于强制阻断的 Hook 协议：仅进程发现与配置扫描。",
    ),
    "hermes": AgentAdapter(
        key="hermes",
        display_name="Hermes Agent",
        tier=DISCOVERY_TIER,
        agent_name="hermes",
        process_comms=("hermes", "hermes-agent"),
        notes="未确认 Hook 协议：仅进程发现；Skills/MCP 做静态盘点，不宣称可阻断。",
    ),
    "opencode": AgentAdapter(
        key="opencode",
        display_name="OpenCode",
        tier=DISCOVERY_TIER,
        agent_name="opencode",
        process_comms=("opencode",),
        notes="未确认 AgentSec Hook 协议：仅进程发现与配置资产盘点。",
    ),
    "aider": AgentAdapter(
        key="aider",
        display_name="Aider",
        tier=DISCOVERY_TIER,
        agent_name="aider",
        process_comms=("aider",),
        notes="未确认 AgentSec Hook 协议：仅进程发现；不把执行后监控描述为阻断。",
    ),
    "stepcode": AgentAdapter(
        key="stepcode",
        display_name="Step Code",
        tier=DISCOVERY_TIER,
        agent_name="stepcode",
        process_comms=("step",),
        notes="支持 MCP/Skills 的 CLI；AgentSec Hook 协议未验证，先按发现层纳管。",
    ),
    "workbuddy": AgentAdapter(
        key="workbuddy",
        display_name="WorkBuddy",
        tier=DISCOVERY_TIER,
        agent_name="workbuddy",
        process_comms=("workbuddy",),
        notes="配置布局未确认：仅进程发现；确认布局后补 scan_paths。",
    ),
    "qcode": AgentAdapter(
        key="qcode",
        display_name="Qcode / Qoder",
        tier=DISCOVERY_TIER,
        agent_name="qcode",
        process_comms=("qcode", "qoder"),
        notes="配置布局未确认：仅进程发现；确认布局后补 scan_paths。",
    ),
}


def get_adapter(key: str) -> AgentAdapter:
    try:
        return ADAPTERS[key]
    except KeyError:
        raise ValueError(
            f"unsupported agent: {key} (known: {', '.join(sorted(ADAPTERS))})"
        ) from None


def hook_tier_keys() -> tuple[str, ...]:
    return tuple(k for k, a in ADAPTERS.items() if a.tier == HOOK_TIER)


def discovery_tier_keys() -> tuple[str, ...]:
    return tuple(k for k, a in ADAPTERS.items() if a.tier == DISCOVERY_TIER)


def known_agent_comms() -> tuple[str, ...]:
    """Every comm the behavior monitor should treat as an Agent main process."""
    comms = {c for a in ADAPTERS.values() for c in a.process_comms}
    return tuple(sorted(comms))


def hook_command(interpreter: str, module: str, adapter: AgentAdapter,
                 subcommand: str) -> str:
    """Command line installed into the product config; carries --agent so the
    hook process knows which adapter (and therefore agent_name) to use."""
    return f'"{interpreter}" -m {module} hook {subcommand} --agent {adapter.key}'


def module_from_command(command: str) -> str:
    """Extract ``-m <module>`` from a hook command, if present."""
    tokens = str(command).replace('"', " ").split()
    for index, token in enumerate(tokens):
        if token == "-m" and index + 1 < len(tokens):
            return tokens[index + 1]
        if token.startswith("-m") and len(token) > 2:
            return token[2:]
    return ""


def encode_pre_decision(adapter: AgentAdapter, decision) -> tuple[int, str, str]:
    """Translate a neutral Decision into the product's PreToolUse protocol.

    Returns ``(exit_code, stdout, stderr)``. Claude Code blocks through the
    documented exit-2 path; Codex (verified against 0.166.0 schemas) blocks
    through ``permissionDecision: "deny"`` JSON on stdout with exit 0. Both
    use the same ``hookSpecificOutput`` JSON for ask.
    """
    reason = decision.reason or "agentsec policy decision"
    if decision.action == SecurityAction.BLOCK:
        if adapter.deny_via == "exit-2":
            return EXIT_BLOCK, "", f"agentsec blocked: {reason}"
        return EXIT_ALLOW, json.dumps({
            "hookSpecificOutput": {
                "hookEventName": adapter.pre_tool_event,
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }, ensure_ascii=False), ""
    if decision.action == SecurityAction.ASK:
        return EXIT_ALLOW, json.dumps({
            "hookSpecificOutput": {
                "hookEventName": adapter.pre_tool_event,
                "permissionDecision": "ask",
                "permissionDecisionReason": reason,
            }
        }, ensure_ascii=False), ""
    return EXIT_ALLOW, "", ""


def _read_config_values(path: Path) -> dict[str, Any]:
    try:
        if path.suffix in {".toml"}:
            with path.open("rb") as handle:
                payload = tomllib.load(handle)
        else:
            payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, tomllib.TOMLDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def read_governance(adapter: AgentAdapter) -> dict[str, Any]:
    """Sandbox/approval posture read from the product's own config file.

    Answers the governance question the hooks layer cannot: what the agent
    is technically allowed to do (sandbox) and when a human must confirm
    (approval). Values come from the product config; the CLI flags
    ``--dangerously-bypass-approvals-and-sandbox`` /
    ``--dangerously-bypass-hook-trust`` are runtime-only and must be audited
    out of band (process cmdline / EDR).
    """
    result: dict[str, Any] = {
        "config_path": "",
        "present": False,
        "settings": {},
        "risks": [],
        "managed_settings": [],
        "notes": [],
    }
    if adapter.governance_file:
        path = Path.home().joinpath(*adapter.governance_file)
        result["config_path"] = str(path)
        values = _read_config_values(path) if path.exists() else {}
        result["present"] = bool(values) or path.exists()
        for check in adapter.governance_checks:
            if check.key not in values:
                continue
            value = values[check.key]
            result["settings"][check.key] = value
            risky = (str(value) in {str(v) for v in check.risky_values}
                     if check.kind == "enum" else bool(value) == bool(check.risky_values[0]))
            if risky:
                result["risks"].append({"key": check.key, "value": value,
                                        "risk": check.risk})
    for relpath in adapter.managed_settings_paths:
        path = Path(*relpath)
        result["managed_settings"].append({"path": str(path),
                                           "present": path.exists()})
    if adapter.trust_hash_pinned:
        result["notes"].append(
            "hook 定义 hash 固定：改动 hooks.json 后需重新 /hooks review，否则不执行")
    return result


def capability_matrix() -> list[dict[str, Any]]:
    """JSON-able capability matrix for the CLI (``guard capabilities``) and API."""
    rows: list[dict[str, Any]] = []
    home = Path.home()
    for adapter in ADAPTERS.values():
        rows.append({
            "key": adapter.key,
            "display_name": adapter.display_name,
            "tier": adapter.tier,
            "agent_name": adapter.agent_name,
            "settings_path": str(home.joinpath(*adapter.settings_relpath))
            if adapter.settings_relpath else "",
            "events": dict(adapter.events),
            "matchers": dict(adapter.matchers),
            "deny_via": adapter.deny_via,
            "trust": list(adapter.trust),
            "trust_hash_pinned": adapter.trust_hash_pinned,
            "process_comms": list(adapter.process_comms),
            "scan_paths": [str(home.joinpath(*p)) for p in adapter.scan_paths],
            "governance": read_governance(adapter),
            "notes": adapter.notes,
        })
    return rows
