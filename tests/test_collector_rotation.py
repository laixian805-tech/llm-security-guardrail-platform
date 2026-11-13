"""审计采集器：日志轮转后游标不能错位。

真实事故：游标以 `source` 为主键，auditd 轮转日志后旧 offset 被带到新文件上，
越界后再也读不到数据，事件时间静默停在 7 小时前。上层所有按时间窗做的关联
（归因、数据流链）因此全部错位——这不是采集器局部问题，是整条链的地基。

所以这里的用例都在验"轮转之后还能不能正确继续"。
"""
from __future__ import annotations

import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "endpoint"))

from audit import collect_once, log_candidates  # noqa: E402

UID = 1000
KEY = "agentsec_test_exec"


def audit_lines(*, serials: list[int], base_ts: float, pid: int = 4321) -> str:
    """构造最小合法 audit 记录：SYSCALL + EOE，能通过 normalize 的过滤。"""
    chunks = []
    for offset, serial in enumerate(serials):
        stamp = base_ts + offset
        chunks.append(
            f'type=SYSCALL msg=audit({stamp:.3f}:{serial}): arch=c000003e syscall=59 '
            f'success=yes exit=0 ppid=1 pid={pid} uid={UID} exe="/usr/bin/bash" '
            f'key="{KEY}"\n')
        chunks.append(f'type=EOE msg=audit({stamp:.3f}:{serial}):\n')
    return "".join(chunks)


def config(log: Path, state: Path) -> dict:
    return {"audit_log": str(log), "state_dir": str(state), "audit_uid": UID,
            "audit_keys": [KEY], "max_records": 1000}


def cursors(state: Path) -> list[tuple]:
    conn = sqlite3.connect(state / "outbox.db")
    try:
        return conn.execute(
            "SELECT source,inode,device,offset FROM collector_cursors ORDER BY inode").fetchall()
    finally:
        conn.close()


@pytest.fixture()
def env(tmp_path):
    log_dir = tmp_path / "audit"
    log_dir.mkdir()
    state = tmp_path / "state"
    state.mkdir()
    return log_dir, state


def test_reads_events_from_a_fresh_log(env):
    log_dir, state = env
    log = log_dir / "audit.log"
    log.write_text(audit_lines(serials=[100, 101], base_ts=1794488000.0), encoding="utf-8")
    result = collect_once(config(log, state))
    assert result["events"] == 2
    assert result["offset"] == log.stat().st_size


def test_rotation_does_not_carry_old_offset_to_new_file(env):
    """核心用例：轮转后必须读新文件，而不是接着旧 offset 找。"""
    log_dir, state = env
    log = log_dir / "audit.log"
    first = audit_lines(serials=[200], base_ts=1794488100.0)
    log.write_text(first, encoding="utf-8")
    assert collect_once(config(log, state))["events"] == 1

    # auditd 轮转：主文件改名，新建空文件
    log.rename(log_dir / "audit.log.1")
    log.write_text(audit_lines(serials=[300], base_ts=1794489000.0, pid=5555), encoding="utf-8")

    result = collect_once(config(log, state))
    assert result["events"] == 1, "轮转后新文件里的事件必须被读到"
    assert result["rotation_gap"] is False

    recorded = cursors(state)
    assert len(recorded) == 2, "两个 inode 应各有一条游标"
    assert all(0 <= row[3] for row in recorded)


def test_current_file_goes_first_then_rotated_tail(env):
    """实时性优先：先读主文件；主文件读完后才补旧文件里未读的尾巴。

    反过来（先补旧文件）会让今天的事件排在十几小时后入库，实测滞后 13 小时，
    上层按时间窗做的关联全部落空——实时性比"严格时间顺序"更重要，缺口仍会补上。
    """
    log_dir, state = env
    log = log_dir / "audit.log"
    log.write_text(audit_lines(serials=[400], base_ts=1794488200.0), encoding="utf-8")
    assert collect_once(config(log, state))["events"] == 1

    # 旧文件追加一条（轮转前写入），然后轮转
    with log.open("a", encoding="utf-8") as handle:
        handle.write(audit_lines(serials=[401], base_ts=1794488210.0, pid=6666))
    log.rename(log_dir / "audit.log.1")
    log.write_text(audit_lines(serials=[500], base_ts=1794489100.0, pid=7777), encoding="utf-8")

    # 第一次：主文件优先，读到今天的事件
    assert collect_once(config(log, state))["events"] == 1
    # 第二次：主文件读完，回去补旧文件的尾巴
    assert collect_once(config(log, state))["events"] == 1


def test_out_of_range_cursor_self_heals(env):
    """游标被写成越界值（历史 bug 的产物）时应重置为 0，而不是永久读不到。"""
    log_dir, state = env
    log = log_dir / "audit.log"
    log.write_text(audit_lines(serials=[600, 601], base_ts=1794488300.0), encoding="utf-8")
    assert collect_once(config(log, state))["events"] == 2

    inode = log.stat().st_ino
    conn = sqlite3.connect(state / "outbox.db")
    conn.execute("UPDATE collector_cursors SET offset=? WHERE inode=?", (10 ** 9, inode))
    conn.commit()
    conn.close()

    result = collect_once(config(log, state))
    assert result["events"] == 2, "越界游标重置后应重新读到内容"


def test_stale_cursor_for_deleted_file_is_reported(env):
    """轮转文件被删除后，游标里留着它的 inode，说明确实丢过数据。"""
    log_dir, state = env
    log = log_dir / "audit.log"
    log.write_text(audit_lines(serials=[700], base_ts=1794488400.0), encoding="utf-8")
    collect_once(config(log, state))

    rotated = log_dir / "audit.log.1"
    log.rename(rotated)
    log.write_text(audit_lines(serials=[800], base_ts=1794489300.0, pid=8888), encoding="utf-8")
    collect_once(config(log, state))
    rotated.unlink()

    result = collect_once(config(log, state))
    assert result["rotation_gap"] is True


def test_log_candidates_reads_current_file_first(env):
    log_dir, _ = env
    log = log_dir / "audit.log"
    log.write_text("x", encoding="utf-8")
    for index in (1, 2):
        candidate = log_dir / f"audit.log.{index}"
        candidate.write_text("x", encoding="utf-8")
        # 让 .1 比 .2 旧
        import os
        stamp = 1000 + (10 - index)
        os.utime(candidate, (stamp, stamp))

    ordered = [path.name for path in log_candidates(log)]
    assert ordered[0] == "audit.log", "主文件必须最先读（实时性优先）"
    assert ordered[1] == "audit.log.1", "补读时先补最近的轮转文件"


def test_ignores_compressed_rotations(env):
    log_dir, _ = env
    log = log_dir / "audit.log"
    log.write_text("x", encoding="utf-8")
    (log_dir / "audit.log.1.gz").write_text("x", encoding="utf-8")
    names = [path.name for path in log_candidates(log)]
    assert "audit.log.1.gz" not in names
