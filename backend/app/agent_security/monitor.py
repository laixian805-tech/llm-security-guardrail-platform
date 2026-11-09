"""auditd parsing, process/session correlation and runtime detection (D2 Linux).

The monitor is the detective layer of the guardrail: it reads auditd records
for execve, sensitive-path access and outbound connects, correlates each
record with an Agent session through the pid -> ppid chain, and emits
normalized ``SecurityEvent`` rows for the platform.

Design notes (landing doc 5.3):
- Only events on the descendant chain of a registered Agent session are
  recorded by default; unrelated system activity is dropped for volume.
- Processes that look like an Agent main process but were never registered
  (e.g. started before the hook was installed) are auto-registered as
  synthetic sessions and flagged with rule S28.
- The monitor cannot block anything; detected risk is recorded with the
  catalog action upgraded to ``alert`` so the SOC can act on it.
"""

from __future__ import annotations

import fnmatch
import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .models import (
    EventSource,
    EventType,
    SecurityAction,
    SecurityEvent,
    Severity,
    utc_now_iso,
)
from .adapters import known_agent_comms
from .policy import (GuardPolicies, classify_sensitive_path,
                    normalize_path, path_matches)
from .redact import redact_value
from .rules import RULES_BY_ID, RUNTIME_RULES_BY_ID, rule_by_id

# Agent main-process names (comm is truncated to 15 chars by the kernel).
# Single source of truth: the per-product capability matrix in adapters.py,
# so discovery-tier products are covered here the moment they are declared.
KNOWN_AGENT_COMMS: tuple[str, ...] = known_agent_comms()

# Commands an Agent legitimately spawns; anything else under a session is
# flagged by rule S24 (unknown_subprocess, audit-only severity).
KNOWN_CHILD_COMMS: frozenset[str] = frozenset({
    "bash", "sh", "zsh", "dash", "fish", "git", "python", "python2", "python3",
    "node", "npm", "npx", "pnpm", "yarn", "deno", "bun", "rg", "grep", "egrep",
    "fgrep", "find", "ls", "cat", "head", "tail", "sed", "awk", "cut", "sort",
    "uniq", "xargs", "wc", "tr", "jq", "make", "cmake", "ninja", "gcc", "g++",
    "cc", "clang", "go", "cargo", "rustc", "java", "javac", "mvn", "gradle",
    "docker", "podman", "kubectl", "helm", "terraform", "tofu", "ansible",
    "ssh", "scp", "sftp", "rsync", "curl", "wget", "tar", "zip", "unzip", "gzip",
    "gunzip", "bzip2", "xz", "7z", "pip", "pip3", "uv", "poetry", "pipx",
    "pytest", "tox", "eslint", "prettier", "tsc", "esbuild", "vite", "webpack",
    "echo", "printf", "env", "which", "whereis", "id", "whoami", "ps", "top",
    "htop", "df", "du", "stat", "file", "diff", "patch", "tee", "mkdir", "rmdir",
    "touch", "cp", "mv", "rm", "ln", "chmod", "chown", "date", "uname", "hostname",
    "sqlite3", "psql", "mysql", "mongosh", "redis-cli", "aws", "gcloud", "az",
    "openssl", "age", "gpg", "dotnet", "ruby", "perl", "php", "R", "julia",
})

# Runtime regex rules applied to execve command lines (same catalog IDs as the
# scanner and the hook guard, so all three layers speak one rule language).
_EXEC_ALERT_RULES: tuple[str, ...] = ("S04", "S05", "S07", "S26", "S27")
_PROD_RULE_ID = "S25"
_ORPHAN_RULE_ID = "S28"
_UNKNOWN_CHILD_RULE_ID = "S24"
_SENSITIVE_PATH_RULE_ID = "S08"

# V1 runtime rules (landing doc 11.2).
_NETWORK_TOOL_RULE_ID = "R003"
_EXFIL_CORRELATION_RULE_ID = "R005"
_NETWORK_TOOL_COMMS: frozenset[str] = frozenset({
    "curl", "wget", "nc", "ncat", "netcat", "socat", "telnet",
    "ftp", "sftp", "scp", "ssh", "rsync",
})
# R005: a sensitive read followed by an outbound connect inside this window
# (same session) is treated as one correlated exfiltration signal.
EXFIL_CORRELATION_WINDOW_SECONDS = 300

_SYSCALL_NAMES: dict[int, str] = {
    59: "execve", 322: "execve", 221: "execve",
    42: "connect", 362: "connect", 203: "connect",
    257: "openat", 2: "open", 87: "unlink", 82: "rename", 90: "chmod",
}

_LINE_RE = re.compile(r"^type=(\S+)\s+msg=audit\((\d+(?:\.\d+)?):(\d+)\):\s*(.*)$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_EPOCH_MIN = 1_000_000_000  # sanity bound for audit epochs


# ---------------------------------------------------------------------------
# auditd log parsing
# ---------------------------------------------------------------------------

@dataclass
class AuditRecord:
    """One grouped auditd event (all lines sharing one audit serial)."""

    serial: str
    epoch: float
    ts: str
    pid: int
    ppid: int
    comm: str
    exe: str
    args: list[str] = field(default_factory=list)
    cwd: str = ""
    paths: list[dict[str, str]] = field(default_factory=list)
    saddr: str = ""
    syscall: int | None = None
    syscall_name: str = ""
    success: bool = True
    key: str = ""


def _parse_body(body: str) -> tuple[dict[str, str], set[str]]:
    """Tokenize ``key=value`` pairs; quoted values keep their raw text."""
    fields: dict[str, str] = {}
    quoted: set[str] = set()
    index = 0
    length = len(body)
    while index < length:
        while index < length and body[index] in " \t":
            index += 1
        if index >= length:
            break
        eq = body.find("=", index)
        if eq == -1:
            break
        key = body[index:eq]
        index = eq + 1
        if index < length and body[index] == '"':
            index += 1
            chars: list[str] = []
            while index < length and body[index] != '"':
                if body[index] == "\\" and index + 1 < length:
                    chars.append(body[index + 1])
                    index += 2
                else:
                    chars.append(body[index])
                    index += 1
            fields[key] = "".join(chars)
            quoted.add(key)
            index += 1
        else:
            end = index
            while end < length and body[end] not in " \t":
                end += 1
            fields[key] = body[index:end]
            index = end
    return fields, quoted


def _maybe_hex_decode(value: str) -> str:
    """auditd hex-encodes unquoted values containing special characters."""
    if not value or len(value) % 2 != 0 or not _HEX_RE.match(value):
        return value
    try:
        raw = bytes.fromhex(value)
        text = raw.decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return value
    if text and all(ch.isprintable() or ch == "\t" for ch in text):
        return text
    return value


def _int_or(value: str, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _build_record(serial: str, epoch: float,
                  group: dict[str, list[tuple[dict[str, str], set[str]]]]) -> AuditRecord | None:
    syscall_lines = group.get("SYSCALL")
    if not syscall_lines:
        return None
    syscall, _ = syscall_lines[0]
    pid = _int_or(syscall.get("pid", ""))
    ppid = _int_or(syscall.get("ppid", ""))
    syscall_no = _int_or(syscall.get("syscall", ""), -1)
    record = AuditRecord(
        serial=serial,
        epoch=epoch,
        ts=datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(),
        pid=pid,
        ppid=ppid,
        comm=syscall.get("comm", ""),
        exe=syscall.get("exe", ""),
        cwd=(group.get("CWD") or [(syscall, set())])[0][0].get("cwd", ""),
        saddr=(group.get("SOCKADDR") or [({}, set())])[0][0].get("saddr", ""),
        syscall=syscall_no if syscall_no >= 0 else None,
        syscall_name=_SYSCALL_NAMES.get(syscall_no, ""),
        success=syscall.get("success", "yes") == "yes",
        key=syscall.get("key", ""),
    )
    for path_fields, _ in group.get("PATH", []):
        name = path_fields.get("name", "")
        if name:
            record.paths.append({
                "name": name,
                "nametype": path_fields.get("nametype", ""),
                "item": path_fields.get("item", ""),
            })
    execve_lines = group.get("EXECVE")
    if execve_lines:
        execve, quoted = execve_lines[0]
        argc = _int_or(execve.get("argc", ""), len(execve))
        for index in range(min(argc, 64)):
            key = f"a{index}"
            if key not in execve:
                break
            record.args.append(execve[key] if key in quoted
                               else _maybe_hex_decode(execve[key]))
    return record


def parse_lines(lines: Iterable[str]) -> list[AuditRecord]:
    """Parse auditd log lines into grouped records; unparseable lines are skipped."""
    records: list[AuditRecord] = []
    current_serial: str | None = None
    group: dict[str, list[tuple[dict[str, str], set[str]]]] = {}

    def flush() -> None:
        if current_serial is not None:
            record = _build_record(current_serial, current_epoch[0], group)
            if record is not None:
                records.append(record)

    current_epoch: list[float] = [0.0]
    for line in lines:
        match = _LINE_RE.match(line)
        if not match:
            continue
        record_type, epoch_text, serial, body = match.groups()
        try:
            epoch = float(epoch_text)
        except ValueError:
            continue
        if serial != current_serial:
            flush()
            group = {}
            current_serial = serial
        current_epoch[0] = epoch
        fields, quoted = _parse_body(body)
        group.setdefault(record_type, []).append((fields, quoted))
    flush()
    return records


def read_new_records(path: Path, start_offset: int = 0) -> tuple[list[AuditRecord], int]:
    """Read records after ``start_offset``; never consumes a partial line.

    Returns the parsed records and the new byte offset, so a crash between
    parsing and cursor persistence cannot lose or duplicate events.
    """
    try:
        size = path.stat().st_size
    except OSError:
        return [], start_offset
    if size < start_offset:  # log rotated or truncated
        start_offset = 0
    try:
        with path.open("rb") as handle:
            handle.seek(start_offset)
            data = handle.read()
    except OSError:
        return [], start_offset
    cut = data.rfind(b"\n")
    if cut == -1:
        return [], start_offset
    lines = data[: cut + 1].decode("utf-8", errors="replace").splitlines()
    return parse_lines(lines), start_offset + cut + 1


def parse_saddr(saddr: str) -> tuple[str, int | None]:
    """Best-effort sockaddr parse: returns (ip, port); ip is '' when unknown."""
    if not saddr or len(saddr) % 2 != 0 or not _HEX_RE.match(saddr):
        return "", None
    try:
        raw = bytes.fromhex(saddr)
    except ValueError:
        return "", None
    if len(raw) < 4:
        return "", None
    family = int.from_bytes(raw[0:2], "little")
    if family == 2 and len(raw) >= 8:  # AF_INET
        port = int.from_bytes(raw[2:4], "big")
        ip = ".".join(str(byte) for byte in reversed(raw[4:8]))
        return ip, port
    return "", None


# ---------------------------------------------------------------------------
# process graph and session correlation
# ---------------------------------------------------------------------------

@dataclass
class ProcInfo:
    pid: int
    ppid: int
    comm: str = ""
    exe: str = ""
    starttime: int = 0
    session_id: str = ""
    registered: bool = False


class ProcessGraph:
    """pid -> ppid/comm graph with session resolution along the ppid chain."""

    def __init__(self, known_agent_comms: Iterable[str] = KNOWN_AGENT_COMMS) -> None:
        self.procs: dict[int, ProcInfo] = {}
        self.known_agent_comms = set(known_agent_comms)

    def add(self, pid: int, ppid: int, *, comm: str = "", exe: str = "",
            starttime: int = 0, session_id: str = "", registered: bool = False) -> None:
        info = self.procs.get(pid)
        if info is None:
            self.procs[pid] = ProcInfo(pid=pid, ppid=ppid, comm=comm, exe=exe,
                                       starttime=starttime, session_id=session_id,
                                       registered=registered)
            return
        info.ppid = ppid or info.ppid
        info.comm = comm or info.comm
        info.exe = exe or info.exe
        info.starttime = starttime or info.starttime
        if session_id:
            info.session_id = session_id
            info.registered = True

    def register_session(self, pid: int, session_id: str) -> None:
        info = self.procs.get(pid)
        if info is None:
            self.add(pid, 0, session_id=session_id, registered=True)
        else:
            info.session_id = session_id
            info.registered = True

    def resolve(self, pid: int) -> tuple[str, int]:
        """Walk the ppid chain; returns (session_id, orphan_root_pid).

        ``orphan_root_pid`` is non-zero when an ancestor looks like an Agent
        main process but no session is registered for it (rule S28).
        """
        visited: set[int] = set()
        current = pid
        for _ in range(64):
            if current in visited or current <= 0:
                break
            visited.add(current)
            info = self.procs.get(current)
            if info is None:
                return "", 0
            if info.session_id:
                return info.session_id, 0
            if info.comm in self.known_agent_comms:
                return "", current
            current = info.ppid
        return "", 0

    def is_agent_process(self, pid: int) -> bool:
        info = self.procs.get(pid)
        if info is None:
            return False
        return info.comm in self.known_agent_comms

    def merge_record(self, record: AuditRecord) -> None:
        self.add(record.pid, record.ppid, comm=record.comm, exe=record.exe)


def load_session_graph(graph: ProcessGraph, sessions: dict[str, dict[str, Any]]) -> None:
    """Seed the graph from hook/proc session registrations (sessions.jsonl)."""
    for entry in sessions.values():
        pid = entry.get("agent_pid")
        session_id = entry.get("session_id")
        if isinstance(pid, int) and pid > 0 and session_id:
            graph.register_session(pid, str(session_id))


# ---------------------------------------------------------------------------
# runtime detection
# ---------------------------------------------------------------------------

@dataclass
class MonitorState:
    """Per-run bookkeeping so once-per-session rules do not repeat."""

    seen_prod_sessions: set[str] = field(default_factory=set)
    seen_orphan_roots: set[int] = field(default_factory=set)
    synthetic_sessions: list[dict[str, Any]] = field(default_factory=list)
    # session_id -> [(epoch, path)] of sensitive reads, for rule R005.
    sensitive_reads: dict[str, list[tuple[float, str]]] = field(default_factory=dict)
    # "session_id|path|read_epoch" keys already reported by R005.
    reported_exfil: set[str] = field(default_factory=set)


def _event_id(dedupe_key: str) -> str:
    return "evt-mon-" + hashlib.sha256(dedupe_key.encode("utf-8")).hexdigest()[:24]


def _base_event(*, event_type: EventType, record: AuditRecord, session_id: str,
                host: str, host_role: str, dedupe_key: str,
                rule_ids: list[str], severity: Severity, action: SecurityAction,
                tool_name: str = "", target_path: str = "", dst_domain: str = "",
                dst_port: int | None = None, evidence: dict[str, Any] | None = None,
                redact: bool = True) -> SecurityEvent:
    payload = redact_value(evidence or {}) if redact else (evidence or {})
    return SecurityEvent(
        event_id=_event_id(dedupe_key),
        ts=record.ts,
        source=EventSource.MONITOR,
        event_type=event_type,
        host=host,
        host_role=host_role,
        session_id=session_id,
        agent_name=record.comm,
        agent_pid=record.pid,
        tool_name=tool_name,
        target_path=target_path,
        dst_domain=dst_domain,
        dst_port=dst_port,
        action=action,
        rule_ids=rule_ids,
        severity=severity,
        evidence=payload,
    )


def _rule_action(rule_ids: list[str]) -> SecurityAction:
    """Detective layer: enforcing rule hits surface as alerts.

    Rules whose catalog action is audit-only (S24/S28) stay audit-level so
    routine observations do not inflate the alert count.
    """
    actions = {rule.action for rid in rule_ids
               if (rule := rule_by_id(rid)) is not None}
    if actions & {SecurityAction.ALERT, SecurityAction.BLOCK, SecurityAction.ASK}:
        return SecurityAction.ALERT
    return SecurityAction.AUDIT


def _max_severity(rule_ids: list[str], default: Severity = Severity.INFO) -> Severity:
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    best = default
    for rule_id in rule_ids:
        rule = rule_by_id(rule_id)
        if rule and order.index(rule.severity) > order.index(best):
            best = rule.severity
    return best


def _prod_session_event(*, session_id: str, host: str, host_role: str,
                        record: AuditRecord, state: MonitorState,
                        policies: GuardPolicies, redact: bool) -> SecurityEvent | None:
    if session_id in state.seen_prod_sessions:
        return None
    state.seen_prod_sessions.add(session_id)
    return _base_event(
        event_type=EventType.PROCESS_EXEC, record=record, session_id=session_id,
        host=host, host_role=host_role, dedupe_key=f"{_PROD_RULE_ID}|{session_id}",
        rule_ids=[_PROD_RULE_ID], severity=RULES_BY_ID[_PROD_RULE_ID].severity,
        action=SecurityAction.ASK, tool_name=record.comm, target_path=record.exe,
        evidence={"signal": "prod_host_session", "comm": record.comm,
                  "exe": record.exe, "serial": record.serial},
        redact=redact,
    )


def _orphan_event(*, root_pid: int, record: AuditRecord, session_id: str,
                  host: str, host_role: str, state: MonitorState,
                  redact: bool) -> SecurityEvent:
    state.seen_orphan_roots.add(root_pid)
    return _base_event(
        event_type=EventType.PROCESS_EXEC, record=record, session_id=session_id,
        host=host, host_role=host_role,
        dedupe_key=f"{_ORPHAN_RULE_ID}|{root_pid}|{record.comm}",
        rule_ids=[_ORPHAN_RULE_ID], severity=RULES_BY_ID[_ORPHAN_RULE_ID].severity,
        action=SecurityAction.ALERT, tool_name=record.comm, target_path=record.exe,
        evidence={"signal": "orphan_session", "root_pid": root_pid,
                  "root_comm": record.comm, "synthetic_session": session_id,
                  "serial": record.serial},
        redact=redact,
    )


def evaluate_record(record: AuditRecord, *, graph: ProcessGraph, host: str,
                    host_role: str, policies: GuardPolicies, state: MonitorState,
                    redact: bool = True) -> list[SecurityEvent]:
    """Turn one audit record into zero or more normalized security events."""
    if not record.success:
        return []
    session_id, orphan_root = graph.resolve(record.pid)
    if not session_id and orphan_root:
        session_id = f"orphan-{orphan_root}"
        graph.register_session(orphan_root, session_id)
        if orphan_root not in state.seen_orphan_roots:
            root_info = graph.procs.get(orphan_root)
            state.synthetic_sessions.append({
                "session_id": session_id,
                "host": host,
                "agent_name": root_info.comm if root_info else "",
                "agent_pid": orphan_root,
                "ppid": root_info.ppid if root_info else 0,
                "user": "",
                "cwd": "",
                "started_at": utc_now_iso(),
                "synthetic": True,
                "orphan": True,
                "source": "monitor",
            })
    if not session_id:
        return []  # outside any Agent tree: dropped for volume control

    events: list[SecurityEvent] = []
    cmdline = " ".join(record.args).strip() or record.comm

    if record.args or record.syscall_name == "execve":
        rule_ids: list[str] = []
        for rule_id in _EXEC_ALERT_RULES:
            rule = RULES_BY_ID.get(rule_id)
            if rule and rule.pattern and re.search(rule.pattern, cmdline):
                rule_ids.append(rule_id)
        if (record.comm and record.comm in _NETWORK_TOOL_COMMS
                and record.comm not in policies.approved_network_tools):
            rule_ids.append(_NETWORK_TOOL_RULE_ID)
        if (record.comm and record.comm not in KNOWN_CHILD_COMMS
                and record.comm not in graph.known_agent_comms):
            rule_ids.append(_UNKNOWN_CHILD_RULE_ID)
        if orphan_root and orphan_root not in state.seen_orphan_roots:
            events.append(_orphan_event(root_pid=orphan_root, record=record,
                                        session_id=session_id, host=host,
                                        host_role=host_role, state=state,
                                        redact=redact))
        if record.args or rule_ids:
            events.append(_base_event(
                event_type=EventType.PROCESS_EXEC, record=record,
                session_id=session_id, host=host, host_role=host_role,
                dedupe_key=f"exec|{record.serial}|{record.pid}",
                rule_ids=rule_ids, severity=_max_severity(rule_ids),
                action=_rule_action(rule_ids), tool_name=record.comm,
                target_path=record.exe,
                evidence={"cmdline": cmdline, "ppid": record.ppid,
                          "cwd": record.cwd, "serial": record.serial,
                          "syscall": record.syscall_name or record.syscall},
                redact=redact,
            ))

    if host and _host_matches(host, policies.prod_hosts):
        prod_event = _prod_session_event(session_id=session_id, host=host,
                                         host_role=host_role, record=record,
                                         state=state, policies=policies,
                                         redact=redact)
        if prod_event is not None:
            events.append(prod_event)

    for item in record.paths:
        normalized = normalize_path(item["name"])
        rule_ids = classify_sensitive_path(normalized)
        if not rule_ids and any(
            path_matches(normalized, pattern) for pattern in policies.block_paths
        ):
            rule_ids = [_SENSITIVE_PATH_RULE_ID]
        if rule_ids:
            state.sensitive_reads.setdefault(session_id, []).append(
                (record.epoch, normalized))
        events.append(_base_event(
            event_type=EventType.FILE_ACCESS, record=record,
            session_id=session_id, host=host, host_role=host_role,
            dedupe_key=f"file|{record.serial}|{record.pid}|{item['name']}",
            rule_ids=rule_ids, severity=_max_severity(rule_ids),
            action=_rule_action(rule_ids), target_path=item["name"],
            evidence={"nametype": item.get("nametype", ""),
                      "watch_perms": "rwa", "comm": record.comm,
                      "cwd": record.cwd, "serial": record.serial},
            redact=redact,
        ))

    if record.saddr:
        ip, port = parse_saddr(record.saddr)
        events.append(_base_event(
            event_type=EventType.NET_CONNECT, record=record,
            session_id=session_id, host=host, host_role=host_role,
            dedupe_key=f"net|{record.serial}|{record.pid}",
            rule_ids=[], severity=Severity.INFO, action=SecurityAction.AUDIT,
            dst_domain=ip, dst_port=port,
            evidence={"saddr": record.saddr, "comm": record.comm,
                      "serial": record.serial,
                      "note": "domain-level detection is DLP/SASE scope"},
            redact=redact,
        ))
        events.extend(_exfil_correlation_events(
            record=record, session_id=session_id, host=host, host_role=host_role,
            state=state, dst_ip=ip, dst_port=port, redact=redact,
        ))
    return events


def _exfil_correlation_events(
    *, record: AuditRecord, session_id: str, host: str, host_role: str,
    state: MonitorState, dst_ip: str, dst_port: int | None, redact: bool,
) -> list[SecurityEvent]:
    """Rule R005: sensitive read in a session followed by an outbound connect.

    The read may have happened in an earlier audit record (or an earlier
    collector cycle within the same process), so reads are kept on
    ``MonitorState`` keyed by session. Each (session, path, read) pair is
    reported at most once.
    """
    events: list[SecurityEvent] = []
    for read_epoch, read_path in state.sensitive_reads.get(session_id, []):
        delta = record.epoch - read_epoch
        if delta < 0 or delta > EXFIL_CORRELATION_WINDOW_SECONDS:
            continue
        key = f"{session_id}|{read_path}|{read_epoch}"
        if key in state.reported_exfil:
            continue
        state.reported_exfil.add(key)
        events.append(_base_event(
            event_type=EventType.NET_CONNECT, record=record,
            session_id=session_id, host=host, host_role=host_role,
            dedupe_key=f"{_EXFIL_CORRELATION_RULE_ID}|{key}|{record.serial}",
            rule_ids=[_EXFIL_CORRELATION_RULE_ID],
            severity=RUNTIME_RULES_BY_ID[_EXFIL_CORRELATION_RULE_ID].severity,
            action=SecurityAction.ALERT,
            dst_domain=dst_ip, dst_port=dst_port,
            evidence={"signal": "sensitive_read_then_connect",
                      "read_path": read_path, "read_epoch": read_epoch,
                      "connect_epoch": record.epoch, "window_seconds":
                      EXFIL_CORRELATION_WINDOW_SECONDS, "comm": record.comm,
                      "saddr": record.saddr, "serial": record.serial},
            redact=redact,
        ))
    return events


def _host_matches(host: str, patterns: tuple[str, ...]) -> bool:
    return bool(host) and any(fnmatch.fnmatch(host, pattern) for pattern in patterns)
