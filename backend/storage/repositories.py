"""领域仓库：DetectorRun、RawReport、Finding。

写路径在一个事务里完成"登记 run → 落原始报告 → 去重写入 Finding → 关联
→ 回填计数"，避免出现计数与关联不一致的中间状态。
"""

from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from domain import DetectorRun, EvidenceRef, Finding, RawReportRef, RunStatus
from storage.schema import connect, migrate

NORMALIZER_VERSION = "asgp-normalizer-1.0.0"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class Storage:
    """SQLite 连接与写锁。SQLite 开发期使用；多设备正式环境换 PostgreSQL。"""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._lock, self.connection() as conn:
            migrate(conn)

    def connection(self) -> sqlite3.Connection:
        return connect(self.path)


class DetectorRunRepository:
    def __init__(self, storage: Storage) -> None:
        self._storage = storage

    # ---------- 读 ----------

    def get(self, run_id: str) -> dict[str, Any] | None:
        with self._storage.connection() as conn:
            row = conn.execute("SELECT * FROM detector_runs WHERE detector_run_id = ?", (run_id,)).fetchone()
        return dict(row) if row else None

    def list(self, *, limit: int = 50, detector_id: str | None = None,
             status: str | None = None) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if detector_id:
            clauses.append("detector_id = ?")
            params.append(detector_id)
        if status:
            clauses.append("status = ?")
            params.append(status)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        with self._storage.connection() as conn:
            rows = conn.execute(
                f"SELECT * FROM detector_runs{where} ORDER BY started_at DESC LIMIT ?", params
            ).fetchall()
        return [dict(row) for row in rows]

    def findings_for_run(self, run_id: str) -> list[dict[str, Any]]:
        with self._storage.connection() as conn:
            rows = conn.execute(
                "SELECT f.* FROM findings f"
                " JOIN detector_run_findings l ON l.finding_id = f.finding_id"
                " WHERE l.detector_run_id = ? ORDER BY f.created_at",
                (run_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def raw_report_for_run(self, run_id: str) -> dict[str, Any] | None:
        with self._storage.connection() as conn:
            row = conn.execute(
                "SELECT * FROM raw_reports WHERE detector_run_id = ?", (run_id,)
            ).fetchone()
        return dict(row) if row else None

    def summary(self) -> dict[str, Any]:
        with self._storage.connection() as conn:
            runs = conn.execute("SELECT COUNT(*) FROM detector_runs").fetchone()[0]
            findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            high = conn.execute(
                "SELECT COUNT(*) FROM findings WHERE severity IN ('high','critical')"
            ).fetchone()[0]
            latest = conn.execute(
                "SELECT MAX(started_at) FROM detector_runs"
            ).fetchone()[0]
        return {
            "scans": runs,
            "findings": findings,
            "high_or_critical": high,
            "latest_scan": latest or "",
        }

    # ---------- 写 ----------

    def create_run(self, *, detector_id: str, detector_version: str, target_ref: str,
                   mode: str, timeout_seconds: int, idempotency_key: str | None = None,
                   asset_id: str | None = None, instance_id: str | None = None) -> str:
        run_id = f"run_{uuid.uuid4().hex[:16]}"
        with self._storage._lock, self._storage.connection() as conn:
            conn.execute(
                "INSERT INTO detector_runs (detector_run_id, idempotency_key, detector_id,"
                " detector_version, asset_id, instance_id, target_ref, mode, status, started_at,"
                " timeout_seconds, normalizer_version, created_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (run_id, idempotency_key, detector_id, detector_version, asset_id, instance_id,
                 target_ref, mode, RunStatus.RUNNING.value, now_iso(), timeout_seconds,
                 NORMALIZER_VERSION, now_iso()),
            )
        return run_id

    def find_by_idempotency_key(self, key: str) -> dict[str, Any] | None:
        with self._storage.connection() as conn:
            row = conn.execute(
                "SELECT * FROM detector_runs WHERE idempotency_key = ?", (key,)
            ).fetchone()
        return dict(row) if row else None

    def record_success(self, *, run_id: str, raw: Any, findings: Iterable[Any],
                       provider_profile_id: str | None = None, model_id: str | None = None,
                       wire_api: str | None = None, latency_ms: int | None = None) -> dict[str, Any]:
        """落原始报告、去重写入 Finding 并收尾 run。

        Finding 按 (detector_id, fingerprint) 去重：重扫同一目标只新增关联，
        不产生重复 Finding。
        """
        raw_report_id = f"raw_{uuid.uuid4().hex[:16]}"
        finished_at = now_iso()
        content = json.dumps(raw.report, ensure_ascii=False, sort_keys=True)
        materialized = list(findings)
        created: list[str] = []

        with self._storage._lock, self._storage.connection() as conn:
            conn.execute("BEGIN")
            try:
                conn.execute(
                    "INSERT INTO raw_reports (raw_report_id, detector_run_id, uri, media_type,"
                    " sha256, byte_length, content, created_at) VALUES (?,?,?,?,?,?,?,?)",
                    (raw_report_id, run_id, f"raw/{run_id}", raw.media_type, raw.sha256,
                     raw.byte_length, content, finished_at),
                )
                for item in materialized:
                    finding_id = f"find_{uuid.uuid4().hex[:16]}"
                    evidence = json.dumps(
                        [ref.model_dump() for ref in item.evidence_refs], ensure_ascii=False
                    )
                    cursor = conn.execute(
                        "INSERT OR IGNORE INTO findings (finding_id, detector_run_id, detector_id,"
                        " detector_version, rule_id, upstream_rule_id, severity, confidence, title,"
                        " message, fingerprint, status, upstream_risk_score, evidence_refs,"
                        " created_at, updated_at)"
                        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (finding_id, run_id, item.detector_id, item.detector_version, item.rule_id,
                         item.upstream_rule_id, item.severity.value, item.confidence.value,
                         item.title, item.message, item.fingerprint, "new",
                         item.upstream_risk_score, evidence, finished_at, finished_at),
                    )
                    if cursor.rowcount:
                        created.append(finding_id)
                    existing = conn.execute(
                        "SELECT finding_id FROM findings WHERE detector_id = ? AND fingerprint = ?",
                        (item.detector_id, item.fingerprint),
                    ).fetchone()
                    conn.execute(
                        "INSERT OR IGNORE INTO detector_run_findings (detector_run_id, finding_id)"
                        " VALUES (?,?)",
                        (run_id, existing["finding_id"]),
                    )
                conn.execute(
                    "UPDATE detector_runs SET status = ?, finished_at = ?, error = NULL,"
                    " finding_count = (SELECT COUNT(*) FROM detector_run_findings WHERE"
                    " detector_run_id = ?), provider_profile_id = ?, model_id = ?, wire_api = ?,"
                    " latency_ms = ? WHERE detector_run_id = ?",
                    (RunStatus.SUCCEEDED.value, finished_at, run_id, provider_profile_id,
                     model_id, wire_api, latency_ms, run_id),
                )
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise

        return {"detector_run_id": run_id, "status": RunStatus.SUCCEEDED.value,
                "finding_count": len(materialized), "created_findings": len(created),
                "raw_report_id": raw_report_id}

    def record_failure(self, *, run_id: str, status: RunStatus, error: str) -> None:
        with self._storage._lock, self._storage.connection() as conn:
            conn.execute(
                "UPDATE detector_runs SET status = ?, finished_at = ?, error = ?, finding_count = 0"
                " WHERE detector_run_id = ?",
                (status.value, now_iso(), error[:2000], run_id),
            )


class ProviderProbeRepository:
    """Provider Probe 结果。按 (provider_id, profile_kind) 只留最新一条。

    落库是为了让"Probe 未通过的 candidate 不进入默认路由"在进程重启后
    依然成立；只存状态和延迟，不存密钥。
    """

    def __init__(self, storage: Storage) -> None:
        self._storage = storage

    def record(self, *, provider_id: str, profile_kind: str, wire_api: str, base_url: str,
               model: str, status: str, latency_ms: int | None, http_status: int | None,
               error_kind: str | None, error: str | None,
               capabilities: list[str]) -> str:
        probe_id = f"probe_{uuid.uuid4().hex[:16]}"
        with self._storage._lock, self._storage.connection() as conn:
            conn.execute(
                "INSERT INTO provider_probes (probe_id, provider_id, profile_kind, wire_api,"
                " base_url, model, status, latency_ms, http_status, error_kind, error,"
                " capabilities, probed_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(provider_id, profile_kind) DO UPDATE SET"
                " probe_id = excluded.probe_id, wire_api = excluded.wire_api,"
                " base_url = excluded.base_url, model = excluded.model,"
                " status = excluded.status, latency_ms = excluded.latency_ms,"
                " http_status = excluded.http_status, error_kind = excluded.error_kind,"
                " error = excluded.error, capabilities = excluded.capabilities,"
                " probed_at = excluded.probed_at",
                (probe_id, provider_id, profile_kind, wire_api, base_url, model, status,
                 latency_ms, http_status, error_kind, error,
                 json.dumps(capabilities, ensure_ascii=False), now_iso()),
            )
        return probe_id

    def latest(self, provider_id: str, profile_kind: str) -> dict[str, Any] | None:
        with self._storage.connection() as conn:
            row = conn.execute(
                "SELECT * FROM provider_probes WHERE provider_id = ? AND profile_kind = ?",
                (provider_id, profile_kind),
            ).fetchone()
        return dict(row) if row else None

    def latest_all(self) -> list[dict[str, Any]]:
        with self._storage.connection() as conn:
            rows = conn.execute("SELECT * FROM provider_probes").fetchall()
        return [dict(row) for row in rows]


def finding_from_row(row: dict[str, Any]) -> Finding:
    return Finding(
        finding_id=row["finding_id"],
        detector_run_id=row["detector_run_id"],
        asset_id=row["asset_id"],
        instance_id=row["instance_id"],
        execution_id=row["execution_id"],
        detector_id=row["detector_id"],
        detector_version=row["detector_version"],
        rule_id=row["rule_id"],
        upstream_rule_id=row["upstream_rule_id"],
        severity=row["severity"],
        confidence=row["confidence"],
        title=row["title"],
        message=row["message"],
        evidence_refs=tuple(EvidenceRef(**ref) for ref in json.loads(row["evidence_refs"] or "[]")),
        fingerprint=row["fingerprint"],
        status=row["status"],
        upstream_risk_score=row["upstream_risk_score"],
        created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
    )


def detector_run_from_row(row: dict[str, Any], raw_report: RawReportRef | None = None) -> DetectorRun:
    return DetectorRun(
        detector_run_id=row["detector_run_id"],
        detector_id=row["detector_id"],
        detector_version=row["detector_version"],
        asset_id=row["asset_id"],
        instance_id=row["instance_id"],
        target_ref=row["target_ref"],
        mode=row["mode"],
        status=row["status"],
        started_at=datetime.fromisoformat(row["started_at"]),
        finished_at=datetime.fromisoformat(row["finished_at"]) if row["finished_at"] else None,
        timeout_seconds=row["timeout_seconds"],
        error=row["error"],
        raw_report=raw_report,
        normalizer_version=row["normalizer_version"],
        finding_count=row["finding_count"],
        provider_profile_id=row["provider_profile_id"],
        model_id=row["model_id"],
        wire_api=row["wire_api"],
        latency_ms=row["latency_ms"],
    )
