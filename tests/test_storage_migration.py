"""存储迁移与去重约束测试。

覆盖：旧原型 scans/findings 两表迁入 DetectorRun/RawReport/Finding；重扫
同一目标不产生重复 Finding；同一次执行的重试不重复登记 DetectorRun。
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from adapters.detectors import RawOutput
from domain import RunStatus
from storage.repositories import DetectorRunRepository, Storage
from storage.schema import DDL, migrate, table_names

LEGACY_DDL = """
CREATE TABLE scans (
    scan_id TEXT PRIMARY KEY, engine TEXT NOT NULL, target TEXT NOT NULL, status TEXT NOT NULL,
    started_at TEXT NOT NULL, finished_at TEXT NOT NULL, finding_count INTEGER NOT NULL,
    summary TEXT NOT NULL, raw_report TEXT NOT NULL);
CREATE TABLE findings (
    finding_id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, engine TEXT NOT NULL, rule_id TEXT NOT NULL,
    title TEXT NOT NULL, severity TEXT NOT NULL, message TEXT NOT NULL, file TEXT NOT NULL,
    line INTEGER NOT NULL, risk_score REAL, metadata TEXT NOT NULL DEFAULT '{}',
    fingerprint TEXT NOT NULL, imported_at TEXT NOT NULL);
"""


def make_legacy_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(LEGACY_DDL)
    conn.execute(
        "INSERT INTO scans VALUES (?,?,?,?,?,?,?,?,?)",
        ("scan_old", "skillspector", "skills/demo", "completed",
         "2026-11-01T00:00:00+00:00", "2026-11-01T00:05:00+00:00", 2, "{}",
         json.dumps({"version": "2.1.0", "runs": []})),
    )
    # 一条有指纹、一条指纹为空（迁移时必须重算，否则撞唯一约束）。
    conn.execute(
        "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("find_a", "scan_old", "skillspector", "P1", "Instruction Override", "critical",
         "detected", "SKILL.md", 8, 9.0, "{}", "fp_a", "2026-11-01T00:05:00+00:00"),
    )
    conn.execute(
        "INSERT INTO findings VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        ("find_b", "scan_old", "skillspector", "PE3", "Credential Access", "high",
         "key read", "SKILL.md", 9, None, "{}", "", "2026-11-01T00:05:00+00:00"),
    )
    conn.commit()
    conn.close()


class TestMigration:
    def test_legacy_rows_become_detector_run_and_findings(self, tmp_path):
        db = tmp_path / "legacy.db"
        make_legacy_db(db)
        Storage(db)

        conn = sqlite3.connect(db)
        conn.row_factory = sqlite3.Row
        run = conn.execute("SELECT * FROM detector_runs WHERE detector_run_id='scan_old'").fetchone()
        assert run is not None
        assert run["detector_id"] == "skillspector"
        # 旧 completed 映射为 succeeded，才不会被显示成失败或 clean 误判。
        assert run["status"] == "succeeded"
        assert run["finding_count"] == 2
        assert run["detector_version"] == "unknown"
        assert run["normalizer_version"] == "legacy-1.0.0"

        raw = conn.execute("SELECT * FROM raw_reports WHERE detector_run_id='scan_old'").fetchone()
        assert raw is not None
        assert json.loads(raw["content"]) == {"version": "2.1.0", "runs": []}

        findings = conn.execute("SELECT * FROM findings ORDER BY rule_id").fetchall()
        assert [f["rule_id"] for f in findings] == ["P1", "PE3"]
        assert findings[1]["fingerprint"], "空指纹必须在迁移时重算"
        # severity 保留，confidence 在旧模型里不存在，记 unknown 不猜测。
        assert findings[0]["severity"] == "critical"
        assert findings[0]["confidence"] == "unknown"

        links = conn.execute("SELECT COUNT(*) FROM detector_run_findings").fetchone()[0]
        assert links == 2

        legacy = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert "scans" not in legacy, "旧 scans 表应已让位"
        assert "scans_legacy" in legacy and "findings_legacy" in legacy, "旧表应保留为 _legacy 供回查"
        # 当前 findings 必须是新表：旧表没有 detector_run_id 和指纹唯一约束。
        columns = {row[1] for row in conn.execute("PRAGMA table_info(findings)")}
        assert "detector_run_id" in columns and "confidence" in columns
        conn.close()

    def test_migration_is_idempotent(self, tmp_path):
        db = tmp_path / "legacy.db"
        make_legacy_db(db)
        Storage(db)
        conn = sqlite3.connect(db)
        migrate(conn)
        migrate(conn)
        assert conn.execute("SELECT COUNT(*) FROM detector_runs").fetchone()[0] == 1
        assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 2
        conn.close()

    def test_fresh_db_has_no_legacy_tables(self, tmp_path):
        Storage(tmp_path / "fresh.db")
        conn = sqlite3.connect(tmp_path / "fresh.db")
        names = table_names(conn)
        assert "detector_runs" in names
        assert "scans" not in names
        assert "findings" in names
        conn.close()


class TestFindingDeduplication:
    @pytest.fixture
    def repo(self, tmp_path):
        return DetectorRunRepository(Storage(tmp_path / "dedup.db"))

    @staticmethod
    def raw() -> RawOutput:
        return RawOutput(report={"findings": []}, media_type="application/json",
                         sha256="a" * 64, byte_length=16)

    @staticmethod
    def finding(rule_id: str, fingerprint: str):
        from adapters.detectors import NormalizedFinding
        from domain import Severity

        return NormalizedFinding(
            rule_id=rule_id, title=f"title {rule_id}", severity=Severity.HIGH,
            message="m", fingerprint=fingerprint,
            detector_id="skillspector", detector_version="2.12.0",
        )

    def test_rescan_does_not_duplicate_findings(self, repo):
        first = repo.create_run(detector_id="skillspector", detector_version="2.12.0",
                                target_ref="skills/demo", mode="static", timeout_seconds=60)
        repo.record_success(run_id=first, raw=self.raw(), findings=[self.finding("P1", "fp_a")])

        second = repo.create_run(detector_id="skillspector", detector_version="2.12.0",
                                 target_ref="skills/demo", mode="static", timeout_seconds=60)
        result = repo.record_success(run_id=second, raw=self.raw(),
                                     findings=[self.finding("P1", "fp_a")])

        with repo._storage.connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            links_first = conn.execute(
                "SELECT COUNT(*) FROM detector_run_findings WHERE detector_run_id=?", (first,)
            ).fetchone()[0]
            links_second = conn.execute(
                "SELECT COUNT(*) FROM detector_run_findings WHERE detector_run_id=?", (second,)
            ).fetchone()[0]

        assert total == 1, "同一指纹不得产生第二条 Finding"
        assert links_first == links_second == 1
        assert result["created_findings"] == 0
        assert result["finding_count"] == 1

    def test_new_finding_in_rescan_is_recorded(self, repo):
        first = repo.create_run(detector_id="skillspector", detector_version="2.12.0",
                                target_ref="skills/demo", mode="static", timeout_seconds=60)
        repo.record_success(run_id=first, raw=self.raw(), findings=[self.finding("P1", "fp_a")])
        second = repo.create_run(detector_id="skillspector", detector_version="2.12.0",
                                 target_ref="skills/demo", mode="static", timeout_seconds=60)
        repo.record_success(run_id=second, raw=self.raw(),
                            findings=[self.finding("P1", "fp_a"), self.finding("PE3", "fp_b")])
        with repo._storage.connection() as conn:
            total = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        assert total == 2

    def test_idempotency_key_prevents_duplicate_run(self, repo):
        key = "scan-key-1"
        repo.create_run(detector_id="skillspector", detector_version="2.12.0",
                        target_ref="skills/demo", mode="static", timeout_seconds=60,
                        idempotency_key=key)
        with pytest.raises(sqlite3.IntegrityError):
            repo.create_run(detector_id="skillspector", detector_version="2.12.0",
                            target_ref="skills/demo", mode="static", timeout_seconds=60,
                            idempotency_key=key)

    def test_failure_is_not_clean(self, repo):
        run_id = repo.create_run(detector_id="skillspector", detector_version="2.12.0",
                                 target_ref="skills/demo", mode="static", timeout_seconds=1)
        repo.record_failure(run_id=run_id, status=RunStatus.TIMED_OUT, error="超时")
        row = repo.get(run_id)
        assert row["status"] == "timed_out"
        assert row["finding_count"] == 0
        assert row["error"]
        assert repo.findings_for_run(run_id) == []

    def test_summary_counts_runs_and_findings(self, repo):
        run_id = repo.create_run(detector_id="skillspector", detector_version="2.12.0",
                                 target_ref="skills/demo", mode="static", timeout_seconds=60)
        repo.record_success(run_id=run_id, raw=self.raw(),
                            findings=[self.finding("P1", "fp_a"), self.finding("PE3", "fp_b")])
        summary = repo.summary()
        assert summary["scans"] == 1
        assert summary["findings"] == 2
        assert summary["high_or_critical"] == 2
        assert summary["latest_scan"]


V4_DDL = """
CREATE TABLE console_users (
    user_id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
    salt TEXT NOT NULL, role TEXT NOT NULL, created_at TEXT NOT NULL, disabled_at TEXT);
CREATE TABLE console_sessions (
    session_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES console_users(user_id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
    revoked_at TEXT);
-- v4 的设备表没有 host_id 与 credential_rotated_at。
CREATE TABLE device_identities (
    device_id TEXT PRIMARY KEY, label TEXT NOT NULL, credential_hash TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL, enrolled_at TEXT NOT NULL, last_seen_at TEXT);
CREATE TABLE schema_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""


def make_v4_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(V4_DDL)
    conn.execute(
        "INSERT INTO device_identities VALUES (?,?,?,?,?,?)",
        ("dev_1", "工作站", "hash_1", "active", "2026-11-01T00:00:00+00:00", None),
    )
    conn.execute("INSERT INTO schema_meta VALUES ('schema_version', '4')")
    conn.commit()
    conn.close()


class TestV5Migration:
    def test_v4_db_gains_execution_tables_and_device_columns(self, tmp_path):
        db = tmp_path / "v4.db"
        make_v4_db(db)
        Storage(db)

        conn = sqlite3.connect(db)
        conn.row_factory = sqlite3.Row
        names = table_names(conn)
        assert {"executions", "intents", "runtime_events"} <= names

        columns = {row[1] for row in conn.execute("PRAGMA table_info(device_identities)")}
        assert "host_id" in columns and "credential_rotated_at" in columns

        # 存量设备的 host 绑定为 NULL：服务端不得替管理员猜一个主机身份。
        device = conn.execute("SELECT * FROM device_identities WHERE device_id='dev_1'").fetchone()
        assert device["host_id"] is None
        assert device["credential_rotated_at"] is None
        assert device["label"] == "工作站", "迁移不得改写存量数据"

        assert conn.execute(
            "SELECT value FROM schema_meta WHERE key='schema_version'"
        ).fetchone()[0] == "5"
        conn.close()

    def test_v5_migration_is_idempotent(self, tmp_path):
        # SQLite 的 ADD COLUMN 不可重复执行，migrate() 必须能连跑。
        db = tmp_path / "v4.db"
        make_v4_db(db)
        Storage(db)
        conn = sqlite3.connect(db)
        migrate(conn)
        migrate(conn)
        host_columns = [row[1] for row in conn.execute("PRAGMA table_info(device_identities)")
                        if row[1] == "host_id"]
        assert host_columns == ["host_id"]
        conn.close()
