from __future__ import annotations

import json
import time
import urllib.error
from pathlib import Path

import pytest

from app.agent_security.collector import (
    CollectorConfig,
    backfill_agent_sessions,
    collect_once,
    collector_status,
    is_agent_process,
    proc_snapshot,
    upload_pending,
)
from app.agent_security.monitor import ProcessGraph
from app.agent_security.store import AgentSecStore

EXEC_RECORD = (
    'type=SYSCALL msg=audit(1761900000.100:1001): arch=c000003e syscall=59 success=yes exit=0 '
    'a0="psql" a1="-h" a2="db.internal" ppid=900 pid=901 auid=1000 uid=1000 '
    'comm="psql" exe="/usr/bin/psql" key="agentsec_exec"\n'
    'type=EXECVE msg=audit(1761900000.100:1001): argc=3 a0="psql" a1="-h" a2="db.internal"\n'
    'type=CWD msg=audit(1761900000.100:1001): cwd="/home/u/proj"\n'
)


@pytest.fixture(autouse=True)
def _isolate(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("AGENTSEC_HOME", str(tmp_path / "agentsec-home"))
    monkeypatch.delenv("AGENTSEC_POLICIES", raising=False)


def _write_proc(root: Path, pid: int, comm: str, ppid: int, *,
                state: str = "S", starttime: int = 4242,
                cmdline: list[str] | None = None) -> None:
    directory = root / str(pid)
    directory.mkdir(parents=True, exist_ok=True)
    stat = (f"{pid} ({comm}) {state} {ppid} {pid} {pid} 0 -1 4194560 100 0 0 0 "
            f"1 2 0 0 20 0 1 0 {starttime}")
    (directory / "stat").write_text(stat, encoding="utf-8")
    if cmdline is not None:
        (directory / "cmdline").write_text("\0".join(cmdline), encoding="utf-8")


def _config(tmp_path: Path, **overrides) -> CollectorConfig:
    proc_root = tmp_path / "proc"
    proc_root.mkdir(exist_ok=True)
    audit_log = tmp_path / "audit.log"
    audit_log.write_text("", encoding="utf-8")
    defaults = dict(
        audit_log=audit_log,
        proc_root=proc_root,
        db_path=tmp_path / "agentsec.db",
        host="d2-dev",
        host_role="dev",
        poll_seconds=0.01,
    )
    defaults.update(overrides)
    return CollectorConfig(**defaults)


def test_proc_snapshot_skips_kernel_threads_and_zombies(tmp_path: Path) -> None:
    proc_root = tmp_path / "proc"
    _write_proc(proc_root, 1, "systemd", 0)
    _write_proc(proc_root, 2, "kthreadd", 0)
    _write_proc(proc_root, 3, "kworker", 2)
    _write_proc(proc_root, 10, "bash", 1, state="Z")
    _write_proc(proc_root, 11, "bash", 1)
    snapshot = proc_snapshot(proc_root)
    assert set(snapshot) == {1, 11}
    assert snapshot[11].ppid == 1
    assert snapshot[11].starttime == 4242


def test_is_agent_process_matches_comm_and_cmdline() -> None:
    assert is_agent_process("claude")
    assert is_agent_process("codex")
    assert not is_agent_process("bash")
    assert not is_agent_process("node", "node\0/usr/lib/my-app/index.js\0")
    assert is_agent_process("node", "node\0/opt/tools/claude\0")


def test_backfill_registers_unregistered_agent(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _write_proc(config.proc_root, 900, "claude", 1, cmdline=["claude"])
    _write_proc(config.proc_root, 901, "bash", 900, cmdline=["bash"])
    store = AgentSecStore(config.db_path)
    graph = ProcessGraph()
    created = backfill_agent_sessions(config, graph, store)
    assert created == ["proc-900-4242"]
    assert graph.resolve(901)[0] == "proc-900-4242"
    sessions = [s for s in store.list_sessions() if s["session_id"] == "proc-900-4242"]
    assert sessions and sessions[0]["agent_name"] == "claude"


def test_collect_once_inserts_events_and_advances_cursor(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.audit_log.write_text(EXEC_RECORD, encoding="utf-8")
    _write_proc(config.proc_root, 900, "claude", 1, cmdline=["claude"])
    stats = collect_once(config, upload=False)
    assert stats["records"] == 1
    assert stats["events"] >= 1
    assert stats["inserted"] >= 1
    assert stats["backfilled_sessions"] == ["proc-900-4242"]
    assert stats["audit_offset"] == config.audit_log.stat().st_size
    assert stats["heartbeat"] is True
    store = AgentSecStore(config.db_path)
    events = store.list_events(session_id="proc-900-4242")
    assert events and "S26" in events[0].rule_ids
    heartbeat = store.list_events(limit=10)
    assert any(e.event_type.value == "heartbeat" for e in heartbeat)


def test_collect_once_second_run_has_no_duplicates(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.audit_log.write_text(EXEC_RECORD, encoding="utf-8")
    _write_proc(config.proc_root, 900, "claude", 1, cmdline=["claude"])
    collect_once(config, upload=False)
    store = AgentSecStore(config.db_path)
    before = len(store.list_events(limit=1000))
    stats = collect_once(config, upload=False)
    after = len(store.list_events(limit=1000))
    assert stats["records"] == 0 and stats["events"] == 0
    assert after == before  # cursor prevents replay; heartbeat is minute-deduped
    assert stats["heartbeat"] is False


def test_upload_pending_marks_events_uploaded(tmp_path: Path, monkeypatch) -> None:
    config = _config(tmp_path, upload_url="http://127.0.0.1:9/api/agent-security/events")
    config.audit_log.write_text(EXEC_RECORD, encoding="utf-8")
    _write_proc(config.proc_root, 900, "claude", 1, cmdline=["claude"])
    collect_once(config, upload=False)
    store = AgentSecStore(config.db_path)
    pending_before = store.pending_events(100)
    assert pending_before

    class _FakeResponse:
        def read(self) -> bytes:
            return json.dumps({"accepted": len(pending_before)}).encode()

        def __enter__(self) -> "_FakeResponse":
            return self

        def __exit__(self, *args) -> bool:
            return False

    monkeypatch.setattr("urllib.request.urlopen",
                        lambda request, timeout=None: _FakeResponse())
    accepted, failed = upload_pending(store, config)
    assert (accepted, failed) == (len(pending_before), 0)
    assert store.pending_events(100) == []


def test_upload_failure_keeps_events_pending(tmp_path: Path, monkeypatch) -> None:
    config = _config(tmp_path, upload_url="http://127.0.0.1:9/api/agent-security/events")
    config.audit_log.write_text(EXEC_RECORD, encoding="utf-8")
    _write_proc(config.proc_root, 900, "claude", 1, cmdline=["claude"])
    collect_once(config, upload=False)
    store = AgentSecStore(config.db_path)

    def _boom(request, timeout=None):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", _boom)
    accepted, failed = upload_pending(store, config)
    assert (accepted, failed) == (0, failed) and failed > 0
    assert store.pending_events(100)
    assert int(store.get_state("upload_fail_count", "0")) >= 1


def test_collector_status_reports_pipeline(tmp_path: Path) -> None:
    config = _config(tmp_path)
    config.audit_log.write_text(EXEC_RECORD, encoding="utf-8")
    _write_proc(config.proc_root, 900, "claude", 1, cmdline=["claude"])
    status = collector_status(config)
    assert status["audit_size"] == config.audit_log.stat().st_size
    assert status["audit_lag_bytes"] == status["audit_size"]
    assert status["heartbeat_overdue"] is True
    assert status["agent_processes"][0]["comm"] == "claude"
    collect_once(config, upload=False)
    status = collector_status(config)
    assert status["audit_lag_bytes"] == 0
    assert status["heartbeat_age_seconds"] is not None
    assert status["heartbeat_overdue"] is False
    assert status["agent_processes"][0]["session_id"] == "proc-900-4242"


def test_r005_sensitive_read_survives_next_collector_cycle(tmp_path: Path) -> None:
    config = _config(tmp_path)
    _write_proc(config.proc_root, 900, "claude", 1, cmdline=["claude"])
    _write_proc(config.proc_root, 901, "bash", 900, cmdline=["bash"])
    base_epoch = time.time()
    first = (
        f'type=SYSCALL msg=audit({base_epoch:.3f}:2001): arch=c000003e syscall=257 success=yes '
        'exit=3 a0=ffffff9c a1=7fffffffe000 pid=901 ppid=900 comm="cat" exe="/bin/cat"\n'
        f'type=PATH msg=audit({base_epoch:.3f}:2001): item=0 name="/tmp/.ssh/id_rsa" '
        'nametype=NORMAL\n'
    )
    config.audit_log.write_text(first, encoding="utf-8")
    collect_once(config, upload=False)
    second = (
        f'type=SYSCALL msg=audit({base_epoch + 45:.3f}:2002): arch=c000003e syscall=42 success=yes '
        'pid=901 ppid=900 comm="curl" exe="/usr/bin/curl"\n'
        f'type=SOCKADDR msg=audit({base_epoch + 45:.3f}:2002): saddr=0200005076433C60'
        '0000000000000000\n'
    )
    config.audit_log.write_text(first + second, encoding="utf-8")
    stats = collect_once(config, upload=False)
    assert stats["records"] == 1
    store = AgentSecStore(config.db_path)
    events = store.list_events(rule_id="R005", session_id="proc-900-4242", limit=20)
    assert len(events) == 1
