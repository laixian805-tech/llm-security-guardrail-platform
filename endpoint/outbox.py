"""有界持久队列。单个 flusher 由 flock 互斥；重启恢复 inflight。

队列有界就意味着会丢数据。丢必须留痕：``drops`` 表记录每一次因容量封顶
而没能入队的批次数与原因，``coverage_cursor`` 记录已经上报到哪一条。
没有这两张表，"网络断开一段时间后缺口有多大"在平台上永远答不出来——
服务端只看到"没有事件"，分不清"没发生"和"丢了"。
"""
import json
import os
import sqlite3
import time
from pathlib import Path


class CapacityExceeded(RuntimeError):
    """队列有界导致的拒绝。调用方必须先在事务外 record_drop 再重新抛出。"""

    def __init__(self, kind: str):
        super().__init__(kind)
        self.kind = kind


def enqueue(outbox, records, session=None):
    """入队；容量拒绝时先留痕再抛。

    留痕必须在事务回滚之后：入队失败时外层 ``with db:`` 回滚整个事务，同一
    连接写下的 drops 会跟着消失——那正是"丢了多少"长期答不出来的原因。
    用独立连接也绕不开，SQLite 只允许一个写者，BEGIN IMMEDIATE 还持着锁。
    """
    try:
        outbox.enqueue_many(records, session=session)
    except CapacityExceeded as exc:
        outbox.record_drop(exc.kind, len(records))
        raise


class Outbox:
    def __init__(self, state_dir, max_records=10000):
        self.root = Path(state_dir)
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = self.root/'outbox.db'
        self.maximum = max_records
        self.db = sqlite3.connect(self.path, timeout=10)
        os.chmod(self.path, 0o600)
        self.db.row_factory = sqlite3.Row
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''CREATE TABLE IF NOT EXISTS outbox (
          seq INTEGER PRIMARY KEY AUTOINCREMENT, record_id TEXT NOT NULL UNIQUE,
          endpoint TEXT NOT NULL, payload TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'pending',
          attempts INTEGER NOT NULL DEFAULT 0, next_attempt REAL NOT NULL DEFAULT 0,
          last_error TEXT, created_at REAL NOT NULL, updated_at REAL NOT NULL);
          CREATE TABLE IF NOT EXISTS sessions (execution_id TEXT PRIMARY KEY, started_at TEXT NOT NULL);
          CREATE INDEX IF NOT EXISTS outbox_state ON outbox(state,seq);
          CREATE TABLE IF NOT EXISTS drops (
            seq INTEGER PRIMARY KEY AUTOINCREMENT, at REAL NOT NULL,
            kind TEXT NOT NULL, count INTEGER NOT NULL, detail TEXT);
          CREATE TABLE IF NOT EXISTS coverage_cursor (key TEXT PRIMARY KEY, value TEXT NOT NULL);''')

    def record_drop(self, kind, count, detail=None):
        """登记一次丢失。

        必须用独立连接写：容量拒绝发生在入队事务内部，外层 ``with self.db``
        会回滚整个事务。丢失痕迹活不过那次回滚的话，"丢了多少"照样答不出来。
        """
        conn = sqlite3.connect(self.path, timeout=10)
        try:
            conn.execute('INSERT INTO drops (at,kind,count,detail) VALUES (?,?,?,?)',
                (time.time(), kind, int(count), detail))
            conn.commit()
        finally:
            conn.close()

    def unreported_drops(self):
        cursor=self.db.execute("SELECT value FROM coverage_cursor WHERE key='drop_seq'").fetchone()
        since=int(cursor['value']) if cursor else 0
        return [dict(r) for r in self.db.execute(
            'SELECT * FROM drops WHERE seq>? ORDER BY seq',(since,)).fetchall()]

    def mark_drops_reported(self, upto):
        with self.db:
            self.db.execute("INSERT INTO coverage_cursor (key,value) VALUES ('drop_seq',?)"
                " ON CONFLICT(key) DO UPDATE SET value=excluded.value",(str(int(upto)),))

    def backlog(self):
        return self.db.execute("SELECT count(*) FROM outbox WHERE state!='sent'").fetchone()[0]

    def high_water(self):
        row=self.db.execute('SELECT max(seq) AS seq FROM outbox').fetchone()
        return row['seq'] or 0

    def enqueue_many(self, records, session=None):
        with self.db:
            self.db.execute('BEGIN IMMEDIATE')
            self.reserve(records)
            if self.path.stat().st_size > 32*1024*1024:
                raise CapacityExceeded('outbox_disk_capacity_exceeded')
            if session:
                self.db.execute('INSERT OR IGNORE INTO sessions VALUES (?,?)', session)
            for record_id, endpoint, payload in records:
                now = time.time()
                self.db.execute('''INSERT OR IGNORE INTO outbox
                    (record_id,endpoint,payload,created_at,updated_at) VALUES (?,?,?,?,?)''',
                    (record_id, endpoint, json.dumps(payload, ensure_ascii=False), now, now))

    def reserve(self, records):
        """容量优先保留未送达记录，已确认送达的数据可提前回收。"""
        identifiers={row[0] for row in records}
        needed=sum(not self.db.execute('SELECT 1 FROM outbox WHERE record_id=?',(rid,)).fetchone() for rid in identifiers)
        count=self.db.execute('SELECT count(*) FROM outbox').fetchone()[0]
        excess=max(0,count+needed-self.maximum)
        if excess:
            # Do not evict an acknowledged record that is part of this same
            # replay batch, otherwise it would need a slot after all.
            for row in self.db.execute("SELECT seq,record_id FROM outbox WHERE state='sent' ORDER BY seq").fetchall():
                if row['record_id'] in identifiers:continue
                self.db.execute('DELETE FROM outbox WHERE seq=?',(row['seq'],))
                excess-=1
                if excess==0:break
        if self.db.execute('SELECT count(*) FROM outbox').fetchone()[0]+needed>self.maximum:
            # 回收已送达记录仍不够：这一批进不了队列。抛给上层在事务外留痕，
            # 在这里直接写 drops 会被随后的回滚抹掉。
            raise CapacityExceeded('outbox_capacity_exceeded')

    def session_start(self, execution_id):
        row = self.db.execute('SELECT started_at FROM sessions WHERE execution_id=?', (execution_id,)).fetchone()
        return row[0] if row else None

    def close(self):
        self.db.close()
