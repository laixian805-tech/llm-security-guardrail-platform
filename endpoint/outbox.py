"""有界持久队列。单个 flusher 由 flock 互斥；重启恢复 inflight。"""
import json
import os
import sqlite3
import time
from pathlib import Path


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
          CREATE INDEX IF NOT EXISTS outbox_state ON outbox(state,seq);''')

    def enqueue_many(self, records, session=None):
        with self.db:
            if self.db.execute("SELECT count(*) FROM outbox").fetchone()[0] + len(records) > self.maximum:
                raise RuntimeError('outbox_capacity_exceeded')
            if self.path.stat().st_size > 32*1024*1024:
                raise RuntimeError('outbox_disk_capacity_exceeded')
            if session:
                self.db.execute('INSERT OR IGNORE INTO sessions VALUES (?,?)', session)
            for record_id, endpoint, payload in records:
                now = time.time()
                self.db.execute('''INSERT OR IGNORE INTO outbox
                    (record_id,endpoint,payload,created_at,updated_at) VALUES (?,?,?,?,?)''',
                    (record_id, endpoint, json.dumps(payload, ensure_ascii=False), now, now))

    def session_start(self, execution_id):
        row = self.db.execute('SELECT started_at FROM sessions WHERE execution_id=?', (execution_id,)).fetchone()
        return row[0] if row else None

    def close(self):
        self.db.close()
