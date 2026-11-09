"""Edge collector daemon: auditd -> normalized events -> local SQLite -> platform.

Runs on the Linux dev machine (D2). One loop iteration:
  1. persist newly discovered Agent main processes as synthetic sessions
     (proc backfill, so Agents started without the SessionStart hook are
     still correlated);
  2. read new auditd records after the stored byte cursor (restart-safe,
     partial lines are never consumed);
  3. evaluate records against the shared rule catalog and insert events;
  4. emit a heartbeat event (platform-side rule S23 detects silence);
  5. batch-upload pending events to the platform when a URL is configured.

The daemon never dies on individual failures: every step is guarded so a
transient audit/log or network error cannot stop collection.
"""

from __future__ import annotations

import json
import os
import random
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .hook import append_session_entry, load_sessions, policies_path
from .models import EventSource, EventType, SecurityAction, SecurityEvent, Severity, utc_now_iso
from .monitor import (
    EXFIL_CORRELATION_WINDOW_SECONDS,
    KNOWN_AGENT_COMMS,
    MonitorState,
    ProcInfo,
    ProcessGraph,
    evaluate_record,
    load_session_graph,
    read_new_records,
)
from .policy import load_policies
from .store import AgentSecStore, default_db_path
from .transport import validate_device_upload_url


@dataclass
class CollectorConfig:
    audit_log: Path = Path("/var/log/audit/audit.log")
    proc_root: Path = Path("/proc")
    db_path: Path | None = None
    upload_url: str = ""
    upload_key: str = ""
    device_key: str = ""
    heartbeat_seconds: int = 60
    poll_seconds: float = 5.0
    batch_limit: int = 500
    host: str = ""
    host_role: str = ""
    redact: bool = True

    def resolved_db_path(self) -> Path:
        return self.db_path or default_db_path()


def load_config() -> CollectorConfig:
    """Build the config from AGENTSEC_* environment variables."""
    return CollectorConfig(
        audit_log=Path(os.environ.get("AGENTSEC_AUDIT_LOG", "/var/log/audit/audit.log")),
        proc_root=Path(os.environ.get("AGENTSEC_PROC_ROOT", "/proc")),
        db_path=Path(os.environ["AGENTSEC_DB_PATH"]) if os.environ.get("AGENTSEC_DB_PATH") else None,
        upload_url=os.environ.get("AGENTSEC_UPLOAD_URL", ""),
        upload_key=os.environ.get("AGENTSEC_UPLOAD_KEY", ""),
        device_key=os.environ.get("AGENTSEC_DEVICE_KEY", ""),
        heartbeat_seconds=int(os.environ.get("AGENTSEC_HEARTBEAT_SECONDS", "60")),
        poll_seconds=float(os.environ.get("AGENTSEC_POLL_SECONDS", "5")),
        batch_limit=int(os.environ.get("AGENTSEC_BATCH_LIMIT", "500")),
        host=os.environ.get("AGENTSEC_HOST") or socket.gethostname(),
        host_role=os.environ.get("AGENTSEC_HOST_ROLE", ""),
        redact=os.environ.get("AGENTSEC_REDACT", "true").lower() != "false",
    )


# ---------------------------------------------------------------------------
# /proc snapshot and Agent process backfill
# ---------------------------------------------------------------------------

def _read_file(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _parse_stat(text: str) -> tuple[str, str, int, int] | None:
    """Return (comm, state, ppid, starttime); comm may contain spaces/parens."""
    if not text:
        return None
    head, _, tail = text.rpartition(")")
    if not head:
        return None
    comm = head[head.index("(") + 1:] if "(" in head else head
    fields = tail.split()
    if len(fields) < 20:
        return None
    try:
        return comm, fields[0], int(fields[1]), int(fields[19])
    except ValueError:
        return None


def proc_snapshot(proc_root: Path) -> dict[int, ProcInfo]:
    """Snapshot live processes; kernel threads and zombies are skipped."""
    infos: dict[int, ProcInfo] = {}
    try:
        entries = list(proc_root.iterdir())
    except OSError:
        return infos
    for entry in entries:
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid == 2:  # kthreadd itself
            continue
        parsed = _parse_stat(_read_file(entry / "stat"))
        if parsed is None:
            continue
        comm, proc_state, ppid, starttime = parsed
        if proc_state == "Z" or ppid == 2:  # zombies and kernel threads
            continue
        try:
            exe = os.readlink(entry / "exe")
        except OSError:
            exe = ""
        infos[pid] = ProcInfo(pid=pid, ppid=ppid, comm=comm, exe=exe,
                              starttime=starttime)
    return infos


def is_agent_process(comm: str, cmdline: str = "") -> bool:
    """Match known Agent main processes by comm or by any cmdline basename."""
    if comm in KNOWN_AGENT_COMMS:
        return True
    return any(Path(token).name in KNOWN_AGENT_COMMS
               for token in cmdline.replace("\0", " ").split() if token)


def _proc_cmdline(proc_root: Path, pid: int) -> str:
    return _read_file(proc_root / str(pid) / "cmdline")


def backfill_agent_sessions(config: CollectorConfig, graph: ProcessGraph,
                            store: AgentSecStore,
                            snapshot: dict[int, ProcInfo] | None = None) -> list[str]:
    """Register Agent main processes missing from the session registry."""
    created: list[str] = []
    if snapshot is None:
        snapshot = proc_snapshot(config.proc_root)
    for pid, info in snapshot.items():
        graph.add(pid, info.ppid, comm=info.comm, exe=info.exe,
                  starttime=info.starttime)
    for pid, info in snapshot.items():
        if graph.procs[pid].session_id:
            continue
        cmdline = _proc_cmdline(config.proc_root, pid)
        if not is_agent_process(info.comm, cmdline):
            continue
        session_id = f"proc-{pid}-{info.starttime}"
        cwd = ""
        try:
            cwd = os.readlink(config.proc_root / str(pid) / "cwd")
        except OSError:
            pass
        entry = {
            "session_id": session_id,
            "host": config.host,
            "agent_name": info.comm,
            "agent_pid": pid,
            "ppid": info.ppid,
            "user": "",
            "cwd": cwd,
            "started_at": utc_now_iso(),
            "synthetic": True,
            "source": "proc-backfill",
        }
        try:
            append_session_entry(entry)
            store.upsert_session(session_id, host=config.host,
                                 agent_name=info.comm, user="", cwd=cwd)
        except OSError:
            continue
        graph.register_session(pid, session_id)
        created.append(session_id)
    return created


# ---------------------------------------------------------------------------
# collection cycle
# ---------------------------------------------------------------------------

def _maybe_heartbeat(store: AgentSecStore, config: CollectorConfig,
                     audit_offset: int) -> bool:
    now = time.time()
    last = store.get_state("last_heartbeat_epoch")
    if last:
        try:
            if now - float(last) < config.heartbeat_seconds:
                return False
        except ValueError:
            pass
    minute = datetime.now(timezone.utc).strftime("%Y%m%d%H%M")
    pending = store.pending_event_stats()
    store.insert_event(SecurityEvent(
        event_id=f"evt-mon-hb-{minute}",
        ts=utc_now_iso(),
        source=EventSource.MONITOR,
        event_type=EventType.HEARTBEAT,
        host=config.host,
        host_role=config.host_role,
        action=SecurityAction.AUDIT,
        severity=Severity.INFO,
        evidence={"collector": "agentsec", "audit_offset": audit_offset,
                  **pending,
                  "upload_fail_count": int(store.get_state("upload_fail_count", "0") or 0),
                  "audit_lost": int(store.get_state("audit_lost", "0") or 0),
                  "poll_seconds": config.poll_seconds,
                  "heartbeat_interval_seconds": config.heartbeat_seconds},
    ))
    store.set_state("last_heartbeat_epoch", str(now))
    store.set_state("last_heartbeat_ts", utc_now_iso())
    return True


def _exfil_key_within_window(key: str, cutoff_epoch: float) -> bool:
    try:
        _prefix, epoch = key.rsplit("|", 1)
        return float(epoch) >= cutoff_epoch
    except (ValueError, TypeError):
        return False


def _exfil_key_within_window(key: str, cutoff_epoch: float) -> bool:
    try:
        _prefix, epoch = key.rsplit("|", 1)
        return float(epoch) >= cutoff_epoch
    except (ValueError, TypeError):
        return False


def collect_once(config: CollectorConfig, *, upload: bool = True) -> dict[str, Any]:
    """Run one collection cycle; returns a stats dict for CLI/status output."""
    store = AgentSecStore(config.resolved_db_path())
    state = MonitorState()
    state.sensitive_reads = store.list_monitor_reads(
        now_epoch=time.time(), window_seconds=EXFIL_CORRELATION_WINDOW_SECONDS)
    try:
        reported = json.loads(store.get_state("monitor_reported_exfil", "[]") or "[]")
        if isinstance(reported, list):
            state.reported_exfil = {str(item) for item in reported}
    except (TypeError, json.JSONDecodeError):
        state.reported_exfil = set()
    graph = ProcessGraph()
    load_session_graph(graph, load_sessions())
    for pid, info in proc_snapshot(config.proc_root).items():
        graph.add(pid, info.ppid, comm=info.comm, exe=info.exe,
                  starttime=info.starttime)

    snapshot = proc_snapshot(config.proc_root)
    backfilled = backfill_agent_sessions(config, graph, store, snapshot)

    offset = int(store.get_state("audit_offset") or 0)
    records, new_offset = read_new_records(config.audit_log, offset)
    for record in records:
        graph.merge_record(record)

    policies = load_policies(policies_path())
    events: list[SecurityEvent] = []
    for record in records:
        events.extend(evaluate_record(
            record, graph=graph, host=config.host, host_role=config.host_role,
            policies=policies, state=state, redact=config.redact,
        ))

    inserted = store.insert_events(events)
    store.save_monitor_reads(
        state.sensitive_reads, now_epoch=time.time(),
        window_seconds=EXFIL_CORRELATION_WINDOW_SECONDS)
    cutoff_epoch = time.time() - EXFIL_CORRELATION_WINDOW_SECONDS
    state.reported_exfil = {
        item for item in state.reported_exfil
        if _exfil_key_within_window(item, cutoff_epoch)
    }
    store.set_state("monitor_reported_exfil",
                    json.dumps(sorted(state.reported_exfil), ensure_ascii=False))
    for entry in state.synthetic_sessions:
        try:
            append_session_entry(entry)
            store.upsert_session(entry["session_id"], host=entry.get("host", ""),
                                 agent_name=entry.get("agent_name", ""),
                                 user=entry.get("user", ""),
                                 cwd=entry.get("cwd", ""))
        except OSError:
            continue
    store.set_state("audit_offset", str(new_offset))

    heartbeat = _maybe_heartbeat(store, config, new_offset)
    uploaded, failed = upload_pending(store, config) if upload else (0, 0)
    return {
        "ts": utc_now_iso(),
        "host": config.host,
        "records": len(records),
        "events": len(events),
        "inserted": inserted,
        "backfilled_sessions": backfilled,
        "orphan_roots": sorted(state.seen_orphan_roots),
        "audit_offset": new_offset,
        "heartbeat": heartbeat,
        "uploaded": uploaded,
        "upload_failed": failed,
    }


def run_daemon(config: CollectorConfig) -> None:
    """Collect forever; individual cycle failures are logged and retried."""
    while True:
        try:
            collect_once(config)
        except Exception as exc:  # never let the daemon die
            print(f"agentsec collector cycle failed: {exc}", flush=True)
        time.sleep(max(1.0, config.poll_seconds))


# ---------------------------------------------------------------------------
# upload
# ---------------------------------------------------------------------------

def upload_pending(store: AgentSecStore, config: CollectorConfig) -> tuple[int, int]:
    """POST pending events to the platform; returns (accepted, still_pending)."""
    if not config.upload_url:
        return 0, 0
    if config.device_key or config.upload_key:
        try:
            validate_device_upload_url(config.upload_url)
        except ValueError:
            failures = int(store.get_state("upload_fail_count", "0") or 0) + 1
            store.set_state("upload_fail_count", str(failures))
            now_epoch = time.time()
            delay = min(300, 5 * (2 ** min(failures - 1, 6))) * random.uniform(0.8, 1.2)
            store.set_state("upload_retry_after_epoch", str(now_epoch + delay))
            return 0, len(store.pending_events(config.batch_limit))
    now_epoch = time.time()
    retry_after = float(store.get_state("upload_retry_after_epoch", "0") or 0)
    if now_epoch < retry_after:
        return 0, len(store.pending_events(config.batch_limit))
    pending = store.pending_events(config.batch_limit)
    if not pending:
        return 0, 0
    body = json.dumps(
        {"events": [event.model_dump(mode="json") for event in pending]},
        ensure_ascii=False,
    ).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if config.device_key:
        headers["X-AgentSec-Device-Key"] = config.device_key
    elif config.upload_key:
        headers["X-AgentSec-Key"] = config.upload_key
    request = urllib.request.Request(config.upload_url, data=body, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = json.loads(response.read().decode("utf-8") or "{}")
        accepted = int(payload.get("accepted", len(pending)))
        rejected = payload.get("rejected", [])
        rejected = rejected if isinstance(rejected, list) else []
        safely_accounted = accepted + len(rejected) == len(pending) and all(
            isinstance(item, dict) and item.get("reason") == "duplicate"
            for item in rejected
        )
        if not safely_accounted:
            failures = int(store.get_state("upload_fail_count", "0") or 0) + 1
            store.set_state("upload_fail_count", str(failures))
            delay = min(300, 5 * (2 ** min(failures - 1, 6))) * random.uniform(0.8, 1.2)
            store.set_state("upload_retry_after_epoch", str(time.time() + delay))
            return accepted, len(pending)
    except (urllib.error.URLError, OSError, ValueError, TimeoutError):
        failures = int(store.get_state("upload_fail_count", "0") or 0) + 1
        store.set_state("upload_fail_count", str(failures))
        delay = min(300, 5 * (2 ** min(failures - 1, 6))) * random.uniform(0.8, 1.2)
        store.set_state("upload_retry_after_epoch", str(now_epoch + delay))
        return 0, len(pending)
    store.set_state("upload_fail_count", "0")
    store.set_state("upload_retry_after_epoch", "0")
    store.mark_uploaded([event.event_id for event in pending])
    return accepted, 0


# ---------------------------------------------------------------------------
# status helpers (used by the CLI)
# ---------------------------------------------------------------------------

def collector_status(config: CollectorConfig) -> dict[str, Any]:
    store = AgentSecStore(config.resolved_db_path())
    offset = int(store.get_state("audit_offset") or 0)
    try:
        size = config.audit_log.stat().st_size
    except OSError:
        size = 0
    last_hb = store.get_state("last_heartbeat_epoch")
    hb_age: float | None = None
    if last_hb:
        try:
            hb_age = round(time.time() - float(last_hb), 1)
        except ValueError:
            hb_age = None
    sessions = load_sessions()
    agents = [info for info in proc_snapshot(config.proc_root).values()
              if is_agent_process(info.comm, _proc_cmdline(config.proc_root, info.pid))]
    return {
        "audit_log": str(config.audit_log),
        "audit_size": size,
        "audit_offset": offset,
        "audit_lag_bytes": max(size - offset, 0),
        "pending_events": len(store.pending_events(1000)),
        "upload_url": config.upload_url or "(local only)",
        "upload_fail_count": int(store.get_state("upload_fail_count", "0") or 0),
        "last_heartbeat_epoch": last_hb,
        "heartbeat_age_seconds": hb_age,
        "heartbeat_overdue": hb_age is None or hb_age > config.heartbeat_seconds * 2,
        "registered_sessions": len(sessions),
        "agent_processes": [
            {"pid": info.pid, "ppid": info.ppid, "comm": info.comm,
             "exe": info.exe, "session_id": graph_session(sessions, info.pid)}
            for info in agents
        ],
    }


def graph_session(sessions: dict[str, dict[str, Any]], pid: int) -> str:
    for entry in sessions.values():
        if entry.get("agent_pid") == pid:
            return str(entry.get("session_id", ""))
    return ""
