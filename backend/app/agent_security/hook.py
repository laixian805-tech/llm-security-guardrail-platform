from __future__ import annotations

import getpass
import json
import os
import socket
import sys
import uuid
from pathlib import Path
from typing import Any

from .adapters import (DEFAULT_AGENT, AgentAdapter, encode_pre_decision,
                       get_adapter)
from .models import (
    Decision,
    EventSource,
    EventType,
    SecurityAction,
    SecurityEvent,
    Severity,
    utc_now_iso,
)
from .policy import CallerContext, decide, load_policies
from .redact import hash_value, redact_value
from .paths import agentsec_dir
from .store import AgentSecStore

EXIT_ALLOW = 0
EXIT_BLOCK = 2
EXIT_USAGE = 1


class PayloadError(Exception):
    """Hook stdin was missing or not a JSON object."""


def read_payload() -> dict[str, Any]:
    """Read the hook JSON payload from stdin.

    Raises :class:`PayloadError` on missing/invalid input: a guard that cannot
    read what it is supposed to check must fail closed (landing doc 4.6), not
    silently treat the call as unobjectionable.
    """
    try:
        raw = sys.stdin.read()
    except (OSError, UnicodeDecodeError) as exc:
        raise PayloadError(f"cannot read hook stdin: {exc}") from exc
    if not raw or not raw.strip():
        raise PayloadError("hook stdin is empty")
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise PayloadError(f"hook stdin is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise PayloadError("hook stdin JSON is not an object")
    return payload


def caller_context(payload: dict[str, Any],
                   adapter: AgentAdapter | None = None) -> CallerContext:
    agent_name = (adapter.agent_name if adapter is not None
                  else os.environ.get("AGENTSEC_AGENT_NAME") or DEFAULT_AGENT)
    return CallerContext(
        host=socket.gethostname(),
        host_role=os.environ.get("AGENTSEC_HOST_ROLE", ""),
        user=os.environ.get("USER") or os.environ.get("USERNAME") or _safe_user(),
        session_id=str(payload.get("session_id", "")),
        agent_name=agent_name,
        cwd=str(payload.get("cwd", "")),
    )


def _safe_user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return ""


def policies_path() -> Path:
    return Path(os.environ.get("AGENTSEC_POLICIES",
                           agentsec_dir() / "policies.json"))


def audit_failures_file() -> Path:
    return agentsec_dir() / "audit-failures.jsonl"


def audit_failure_count() -> int:
    """Number of audit writes that failed since the last reset.

    The acceptance metric is "event completeness >= 99%"; without this
    counter a silently dropped audit event is indistinguishable from an
    event that never happened.
    """
    target = audit_failures_file()
    if not target.exists():
        return 0
    try:
        return sum(1 for line in target.read_text(encoding="utf-8").splitlines()
                   if line.strip())
    except OSError:
        return 0


def _record_audit_failure(reason: str) -> None:
    try:
        target = audit_failures_file()
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"ts": utc_now_iso(), "reason": reason[:300]},
                                    ensure_ascii=False) + "\n")
    except Exception:
        pass


def audit(event_type: EventType, *, decision: Decision | None = None,
          tool_name: str = "", tool_input: dict[str, Any] | None = None,
          ctx: CallerContext | None = None, severity: Severity | None = None,
          target_path: str = "", extra_evidence: dict[str, Any] | None = None) -> str:
    """Write one audit event to the local store; audit must never break the hook."""
    try:
        evidence: dict[str, Any] = {"reason": decision.reason if decision else "",
                                    "matched_signals": decision.matched_signals if decision else []}
        if tool_input is not None:
            evidence["args_sha256"] = hash_value(json.dumps(tool_input, sort_keys=True,
                                                            ensure_ascii=False))
            if os.environ.get("AGENTSEC_HOOK_KEEP_INPUT") == "1":
                evidence["tool_input"] = redact_value(tool_input)
        if extra_evidence:
            evidence.update(extra_evidence)
        store = AgentSecStore()
        event_id = f"evt-{uuid.uuid4().hex}"
        store.insert_event(SecurityEvent(
            event_id=event_id,
            ts=utc_now_iso(),
            source=EventSource.HOOK,
            event_type=event_type,
            host=ctx.host if ctx else "",
            host_role=ctx.host_role if ctx else "",
            session_id=ctx.session_id if ctx else "",
            agent_name=ctx.agent_name if ctx else "",
            agent_pid=os.getppid(),
            tool_name=tool_name,
            target_path=target_path,
            action=decision.action if decision else SecurityAction.AUDIT,
            rule_ids=decision.rule_ids if decision else [],
            severity=severity if severity is not None else Severity.INFO,
            evidence=evidence,
        ))
        return event_id
    except Exception as exc:
        # Audit failures must not change the enforcement outcome, but they
        # must be counted: silent loss breaks the event-completeness metric.
        _record_audit_failure(str(exc))
        return ""


def sessions_file() -> Path:
    return agentsec_dir() / "sessions.jsonl"


def append_session_entry(entry: dict[str, Any]) -> None:
    """Append one session registration line; shared by hook and collector."""
    sessions_file().parent.mkdir(parents=True, exist_ok=True)
    with sessions_file().open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(entry, ensure_ascii=False) + "\n")


def register_session(ctx: CallerContext, payload: dict[str, Any]) -> None:
    append_session_entry({
        "session_id": ctx.session_id,
        "host": ctx.host,
        "agent_name": ctx.agent_name,
        "agent_pid": os.getppid(),
        "ppid": os.getppid(),
        "user": ctx.user,
        "cwd": str(payload.get("cwd", "")),
        "started_at": utc_now_iso(),
    })


def load_sessions() -> dict[str, dict[str, Any]]:
    """Latest registration per session_id; consumed by the monitor collector."""
    target = sessions_file()
    if not target.exists():
        return {}
    sessions: dict[str, dict[str, Any]] = {}
    for line in target.read_text(encoding="utf-8").splitlines():
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(entry, dict) and entry.get("session_id"):
            sessions[str(entry["session_id"])] = entry
    return sessions


def _payload_fields(payload: dict[str, Any], adapter: AgentAdapter) -> tuple[str, dict[str, Any]]:
    keys = adapter.input_keys
    tool_name = str(payload.get(keys.get("tool_name", "tool_name"), ""))
    tool_input = payload.get(keys.get("tool_input", "tool_input")) or {}
    if not isinstance(tool_input, dict):
        tool_input = {}
    return tool_name, tool_input


def _emit_decision(adapter: AgentAdapter, decision: Decision, *, tool_name: str,
                   tool_input: dict[str, Any], ctx: CallerContext) -> int:
    """Audit the decision, then render it in the product's own protocol."""
    severity = Severity.HIGH if decision.action == SecurityAction.BLOCK else (
        Severity.MEDIUM if decision.action == SecurityAction.ASK else Severity.INFO)
    # The decision is evaluated against the payload cwd (relative paths), so
    # the audit trail must carry it, not just the sessions table.
    extra = {"cwd": ctx.cwd} if ctx.cwd else None
    event_id = audit(EventType.TOOL_CALL, decision=decision, tool_name=tool_name,
          tool_input=tool_input, ctx=ctx, severity=severity,
          extra_evidence=extra)
    code, out, err = encode_pre_decision(adapter, decision)
    if out:
        print(out)
    if err:
        print(err, file=sys.stderr)
    try:
        if not event_id:
            return code
        AgentSecStore().record_runtime_enforcement({
            "enforcement_id": f"enf-{uuid.uuid4().hex}",
            "event_id": event_id,
            "requested_action": decision.action.value,
            "actual_action": decision.action.value,
            "product_ack": True,
            "exit_code": code,
            "enforcement_result": "enforced",
            "adapter_version": adapter.key,
            "ts": utc_now_iso(),
        })
    except Exception as exc:
        _record_audit_failure(f"runtime enforcement write: {exc}")
    return code


def pre_tool_use(adapter: AgentAdapter | None = None) -> int:
    adapter = adapter or get_adapter(DEFAULT_AGENT)
    try:
        payload = read_payload()
    except PayloadError as exc:
        # Fail closed: an unreadable payload means the check never ran, so the
        # call must not proceed as if it had passed (landing doc 4.6).
        ctx = caller_context({}, adapter)
        decision = Decision(
            action=SecurityAction.BLOCK,
            rule_ids=["payload_error"],
            matched_signals=["hook_payload_error"],
            reason=f"unreadable hook payload, failing closed: {exc}",
        )
        return _emit_decision(adapter, decision, tool_name="", tool_input={}, ctx=ctx)
    ctx = caller_context(payload, adapter)
    tool_name, tool_input = _payload_fields(payload, adapter)
    decision = _skill_read_admission(tool_name, tool_input, ctx)
    if decision is None:
        decision = decide(tool_name, tool_input, ctx, load_policies(policies_path()))
    return _emit_decision(adapter, decision, tool_name=tool_name,
                          tool_input=tool_input, ctx=ctx)


def post_tool_use(adapter: AgentAdapter | None = None) -> int:
    adapter = adapter or get_adapter(DEFAULT_AGENT)
    try:
        payload = read_payload()
    except PayloadError as exc:
        audit(EventType.TOOL_CALL, decision=Decision(
            action=SecurityAction.ALERT, rule_ids=["payload_error"],
            matched_signals=["hook_payload_error"],
            reason=f"unreadable hook payload after tool use: {exc}"),
            ctx=caller_context({}, adapter), severity=Severity.MEDIUM)
        return EXIT_ALLOW
    ctx = caller_context(payload, adapter)
    tool_name, tool_input = _payload_fields(payload, adapter)
    _record_skill_use(tool_name, tool_input, ctx)
    audit(EventType.TOOL_CALL, tool_name=tool_name, tool_input=tool_input, ctx=ctx,
          severity=Severity.INFO)
    return EXIT_ALLOW


def _read_target(tool_name: str, tool_input: dict[str, Any]) -> Path | None:
    if tool_name.lower() not in {"read", "read_file", "cat", "view"}:
        return None
    raw_path = tool_input.get("file_path") or tool_input.get("path")
    if not isinstance(raw_path, str) or not raw_path.strip():
        return None
    try:
        return Path(raw_path).expanduser().resolve(strict=False)
    except (OSError, RuntimeError):
        return None


def _matching_skill_asset(target: Path, ctx: CallerContext):
    from .store import AgentSecStore

    try:
        assets = AgentSecStore().list_assets(kind="skill")
    except Exception:
        return None
    matches = []
    for asset in assets:
        try:
            root = Path(asset.path).expanduser().resolve(strict=False)
            target.relative_to(root)
        except (OSError, RuntimeError, ValueError):
            continue
        matches.append(asset)
    return max(matches, key=lambda asset: len(Path(asset.path).parts), default=None)


def _skill_read_admission(tool_name: str, tool_input: dict[str, Any],
                          ctx: CallerContext) -> Decision | None:
    target = _read_target(tool_name, tool_input)
    if target is None:
        return None
    asset = _matching_skill_asset(target, ctx)
    if asset is None:
        return None
    if asset.risk_assessment.value in {"high_risk_candidate", "confirmed_malicious"}:
        return Decision(
            action=SecurityAction.BLOCK,
            rule_ids=["ADMISSION_SKILL_RISK"],
            matched_signals=["skill_asset_high_risk"],
            reason=f"Skill asset {asset.name} is blocked by its current risk assessment",
        )
    if asset.risk_assessment.value == "suspicious":
        return Decision(
            action=SecurityAction.ASK,
            rule_ids=["ADMISSION_SKILL_REVIEW"],
            matched_signals=["skill_asset_requires_review"],
            reason=f"Skill asset {asset.name} requires review before reading",
        )
    return None


def _record_skill_use(tool_name: str, tool_input: dict[str, Any],
                      ctx: CallerContext) -> None:
    target = _read_target(tool_name, tool_input)
    if target is None:
        return
    asset = _matching_skill_asset(target, ctx)
    if asset is None:
        return
    from .store import AgentSecStore

    try:
        AgentSecStore().mark_asset_used(asset.asset_id)
    except Exception as exc:
        _record_audit_failure(f"skill activity update: {exc}")


def session_start(adapter: AgentAdapter | None = None) -> int:
    adapter = adapter or get_adapter(DEFAULT_AGENT)
    try:
        payload = read_payload()
    except PayloadError as exc:
        audit(EventType.CONFIG_CHANGE, decision=Decision(
            action=SecurityAction.ALERT, rule_ids=["payload_error"],
            matched_signals=["hook_payload_error"],
            reason=f"unreadable hook payload at session start: {exc}"),
            ctx=caller_context({}, adapter), severity=Severity.MEDIUM)
        return EXIT_ALLOW
    ctx = caller_context(payload, adapter)
    register_session(ctx, payload)
    try:
        AgentSecStore().upsert_session(
            ctx.session_id, host=ctx.host, agent_name=ctx.agent_name,
            user=ctx.user, cwd=ctx.cwd,
        )
    except Exception as exc:
        _record_audit_failure(f"session_start upsert: {exc}")
    return EXIT_ALLOW


def session_end(adapter: AgentAdapter | None = None) -> int:
    adapter = adapter or get_adapter(DEFAULT_AGENT)
    try:
        payload = read_payload()
    except PayloadError as exc:
        audit(EventType.CONFIG_CHANGE, decision=Decision(
            action=SecurityAction.ALERT, rule_ids=["payload_error"],
            matched_signals=["hook_payload_error"],
            reason=f"unreadable hook payload at session end: {exc}"),
            ctx=caller_context({}, adapter), severity=Severity.MEDIUM)
        return EXIT_ALLOW
    ctx = caller_context(payload, adapter)
    try:
        AgentSecStore().upsert_session(ctx.session_id, host=ctx.host,
                                       agent_name=ctx.agent_name, ended=True)
    except Exception as exc:
        _record_audit_failure(f"session_end upsert: {exc}")
    return EXIT_ALLOW


HANDLERS = {
    "pre-tool-use": pre_tool_use,
    "post-tool-use": post_tool_use,
    "session-start": session_start,
    "session-end": session_end,
}


def _parse_agent(argv: list[str]) -> str:
    agent = DEFAULT_AGENT
    rest: list[str] = []
    index = 0
    while index < len(argv):
        token = argv[index]
        if token == "--agent" and index + 1 < len(argv):
            agent = argv[index + 1]
            index += 2
            continue
        if token.startswith("--agent="):
            agent = token.split("=", 1)[1]
            index += 1
            continue
        rest.append(token)
        index += 1
    if rest:
        raise ValueError(f"unexpected hook arguments: {' '.join(rest)}")
    return agent


def main(argv: list[str]) -> int:
    if not argv or argv[0] not in HANDLERS:
        print(f"usage: python -m <agentsec-module> hook "
              f"{'|'.join(HANDLERS)} [--agent <product>]",
              file=sys.stderr)
        return EXIT_USAGE
    try:
        agent = _parse_agent(list(argv[1:]))
        adapter = get_adapter(agent)
    except ValueError as exc:
        print(f"agentsec hook error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    return HANDLERS[argv[0]](adapter)
