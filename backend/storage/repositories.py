"""领域仓库：DetectorRun、RawReport、Finding。

写路径在一个事务里完成"登记 run → 落原始报告 → 去重写入 Finding → 关联
→ 回填计数"，避免出现计数与关联不一致的中间状态。
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from domain import (
    ActorKind,
    AuditEvent,
    AuditOutcome,
    ConsoleRole,
    ConsoleSession,
    ConsoleUser,
    DetectorRun,
    DeviceIdentity,
    DeviceStatus,
    EvidenceRef,
    Finding,
    Permission,
    RawReportRef,
    RetentionKind,
    RetentionRule,
    RunStatus,
)
from storage.schema import connect, migrate

NORMALIZER_VERSION = "asgp-normalizer-1.0.0"

# PBKDF2 迭代次数。控制台是低频登录，取一个在普通硬件上约几百毫秒的值。
PBKDF2_ITERATIONS = 240_000


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def hash_password(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), bytes.fromhex(salt), PBKDF2_ITERATIONS
    ).hex()


def hash_token(token: str) -> str:
    """会话令牌只存哈希；令牌本身只在创建时返回一次。"""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class Storage:
    """SQLite 连接与写锁。SQLite 开发期使用；多设备正式环境换 PostgreSQL。"""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._lock, self.connection() as conn:
            migrate(conn)

    @property
    def dialect(self) -> str:
        return "sqlite"

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


def _parse_iso(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


class ConsoleAuthRepository:
    """控制台用户与会话。

    只存密码哈希和会话令牌哈希；明文密码和令牌都不落库。设备身份单独一张
    表，权限模型不共用——设备令牌不代表控制台用户。
    """

    def __init__(self, storage: Storage) -> None:
        self._storage = storage

    def count_users(self) -> int:
        with self._storage.connection() as conn:
            return conn.execute("SELECT COUNT(*) FROM console_users").fetchone()[0]

    def create_user(self, *, username: str, password: str, role: ConsoleRole) -> str:
        user_id = f"user_{uuid.uuid4().hex[:16]}"
        salt = secrets.token_hex(16)
        with self._storage._lock, self._storage.connection() as conn:
            conn.execute(
                "INSERT INTO console_users (user_id, username, password_hash, salt, role,"
                " created_at) VALUES (?,?,?,?,?,?)",
                (user_id, username, hash_password(password, salt), salt, role.value, now_iso()),
            )
        return user_id

    def find_user(self, username: str) -> dict[str, Any] | None:
        with self._storage.connection() as conn:
            row = conn.execute(
                "SELECT * FROM console_users WHERE username = ?", (username,)
            ).fetchone()
        return dict(row) if row else None

    def get_user(self, user_id: str) -> dict[str, Any] | None:
        with self._storage.connection() as conn:
            row = conn.execute(
                "SELECT * FROM console_users WHERE user_id = ?", (user_id,)
            ).fetchone()
        return dict(row) if row else None

    def list_users(self) -> list[dict[str, Any]]:
        with self._storage.connection() as conn:
            rows = conn.execute(
                "SELECT user_id, username, role, created_at, disabled_at FROM console_users"
                " ORDER BY created_at"
            ).fetchall()
        return [dict(row) for row in rows]

    def verify_password(self, row: dict[str, Any], password: str) -> bool:
        candidate = hash_password(password, row["salt"])
        return secrets.compare_digest(candidate, row["password_hash"])

    def set_password(self, *, user_id: str, password: str) -> None:
        salt = secrets.token_hex(16)
        with self._storage._lock, self._storage.connection() as conn:
            conn.execute(
                "UPDATE console_users SET password_hash = ?, salt = ? WHERE user_id = ?",
                (hash_password(password, salt), salt, user_id),
            )

    def set_role(self, *, user_id: str, role: ConsoleRole) -> None:
        with self._storage._lock, self._storage.connection() as conn:
            conn.execute(
                "UPDATE console_users SET role = ? WHERE user_id = ?", (role.value, user_id)
            )

    def set_disabled(self, *, user_id: str, disabled: bool) -> None:
        with self._storage._lock, self._storage.connection() as conn:
            conn.execute(
                "UPDATE console_users SET disabled_at = ? WHERE user_id = ?",
                (now_iso() if disabled else None, user_id),
            )
            if disabled:
                # 禁用用户时同时吊销会话，避免已发出的令牌继续可用。
                conn.execute(
                    "UPDATE console_sessions SET revoked_at = ? WHERE user_id = ?"
                    " AND revoked_at IS NULL",
                    (now_iso(), user_id),
                )

    def create_session(self, *, user_id: str, ttl_seconds: int) -> tuple[str, str]:
        """返回 (session_id, 明文令牌)。令牌只在这里出现一次。"""
        session_id = f"sess_{uuid.uuid4().hex[:16]}"
        token = secrets.token_urlsafe(32)
        created = datetime.now(timezone.utc)
        with self._storage._lock, self._storage.connection() as conn:
            conn.execute(
                "INSERT INTO console_sessions (session_id, user_id, token_hash, created_at,"
                " expires_at) VALUES (?,?,?,?,?)",
                (session_id, user_id, hash_token(token), created.isoformat(),
                 (created + timedelta(seconds=ttl_seconds)).isoformat()),
            )
        return session_id, token

    def resolve_session(self, token: str) -> dict[str, Any] | None:
        with self._storage.connection() as conn:
            row = conn.execute(
                "SELECT s.*, u.username, u.role, u.disabled_at FROM console_sessions s"
                " JOIN console_users u ON u.user_id = s.user_id"
                " WHERE s.token_hash = ?",
                (hash_token(token),),
            ).fetchone()
        return dict(row) if row else None

    def revoke_session(self, session_id: str) -> None:
        with self._storage._lock, self._storage.connection() as conn:
            conn.execute(
                "UPDATE console_sessions SET revoked_at = ? WHERE session_id = ?"
                " AND revoked_at IS NULL",
                (now_iso(), session_id),
            )

    def purge_expired_sessions(self, *, now: datetime) -> int:
        with self._storage._lock, self._storage.connection() as conn:
            cursor = conn.execute(
                "DELETE FROM console_sessions WHERE expires_at < ?", (now.isoformat(),)
            )
            return cursor.rowcount


def console_user_from_row(row: dict[str, Any]) -> ConsoleUser:
    return ConsoleUser(
        user_id=row["user_id"],
        username=row["username"],
        role=ConsoleRole(row["role"]),
        created_at=datetime.fromisoformat(row["created_at"]),
        disabled_at=_parse_iso(row["disabled_at"]),
    )


def console_session_from_row(row: dict[str, Any]) -> ConsoleSession:
    return ConsoleSession(
        session_id=row["session_id"],
        user_id=row["user_id"],
        created_at=datetime.fromisoformat(row["created_at"]),
        expires_at=datetime.fromisoformat(row["expires_at"]),
        revoked_at=_parse_iso(row["revoked_at"]),
    )


class AuditRepository:
    """请求审计。只记 request/event ID 和脱敏后的摘要，不记密钥和原始内容。"""

    def __init__(self, storage: Storage) -> None:
        self._storage = storage

    def record(self, *, request_id: str, actor_kind: ActorKind, actor_id: str, action: str,
               resource: str, outcome: AuditOutcome, detail: dict | None = None) -> str:
        audit_id = f"audit_{uuid.uuid4().hex[:16]}"
        with self._storage._lock, self._storage.connection() as conn:
            conn.execute(
                "INSERT INTO audit_events (audit_id, occurred_at, request_id, actor_kind,"
                " actor_id, action, resource, outcome, detail) VALUES (?,?,?,?,?,?,?,?,?)",
                (audit_id, now_iso(), request_id, actor_kind.value, actor_id, action,
                 resource, outcome.value, json.dumps(detail or {}, ensure_ascii=False)),
            )
        return audit_id

    def list(self, *, limit: int = 100, actor_kind: str | None = None,
             action: str | None = None, since: str | None = None) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if actor_kind:
            clauses.append("actor_kind = ?")
            params.append(actor_kind)
        if action:
            clauses.append("action = ?")
            params.append(action)
        if since:
            clauses.append("occurred_at >= ?")
            params.append(since)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        with self._storage.connection() as conn:
            rows = conn.execute(
                f"SELECT * FROM audit_events{where} ORDER BY occurred_at DESC LIMIT ?", params
            ).fetchall()
        return [dict(row) for row in rows]

    def delete_before(self, cutoff: str) -> int:
        with self._storage._lock, self._storage.connection() as conn:
            cursor = conn.execute("DELETE FROM audit_events WHERE occurred_at < ?", (cutoff,))
            return cursor.rowcount


def audit_event_from_row(row: dict[str, Any]) -> AuditEvent:
    return AuditEvent(
        audit_id=row["audit_id"],
        occurred_at=datetime.fromisoformat(row["occurred_at"]),
        request_id=row["request_id"],
        actor_kind=ActorKind(row["actor_kind"]),
        actor_id=row["actor_id"],
        action=row["action"],
        resource=row["resource"],
        outcome=AuditOutcome(row["outcome"]),
        detail=json.loads(row["detail"] or "{}"),
    )


DEFAULT_RETENTION_DAYS: dict[RetentionKind, int] = {
    RetentionKind.DETECTOR_RUNS: 90,
    RetentionKind.RAW_REPORTS: 30,
    RetentionKind.AUDIT_EVENTS: 365,
    RetentionKind.EXECUTIONS: 90,
    RetentionKind.RUNTIME_EVENTS: 30,
}


class RetentionRepository:
    """扫描与运行数据的保留策略与清理。

    删除顺序要紧：先解除 run 与 Finding 的链接，再把 originating run 已过期
    但仍在别处被引用的 Finding 置空，最后才删 run。直接删 run 会让 Finding
    被级联删掉，牵连仍在保留期内的其它 run。Execution 相反：过期即整条消失，
    子观测没有独立保留价值。
    """

    def __init__(self, storage: Storage) -> None:
        self._storage = storage

    def rules(self) -> list[dict[str, Any]]:
        with self._storage.connection() as conn:
            rows = conn.execute("SELECT * FROM retention_rules").fetchall()
        return [dict(row) for row in rows]

    def ensure_defaults(self) -> None:
        with self._storage._lock, self._storage.connection() as conn:
            for kind, days in DEFAULT_RETENTION_DAYS.items():
                conn.execute(
                    "INSERT INTO retention_rules (data_kind, retention_days, enabled, updated_at)"
                    " VALUES (?,?,1,?) ON CONFLICT(data_kind) DO NOTHING",
                    (kind.value, days, now_iso()),
                )

    def set_rule(self, *, data_kind: RetentionKind, retention_days: int,
                 enabled: bool) -> None:
        with self._storage._lock, self._storage.connection() as conn:
            conn.execute(
                "INSERT INTO retention_rules (data_kind, retention_days, enabled, updated_at)"
                " VALUES (?,?,?,?) ON CONFLICT(data_kind) DO UPDATE SET"
                " retention_days = excluded.retention_days, enabled = excluded.enabled,"
                " updated_at = excluded.updated_at",
                (data_kind.value, retention_days, 1 if enabled else 0, now_iso()),
            )

    def prune(self, *, now: datetime) -> dict[str, int]:
        counts = {kind.value: 0 for kind in RetentionKind}
        rules = {row["data_kind"]: row for row in self.rules()}
        with self._storage._lock, self._storage.connection() as conn:
            conn.execute("BEGIN")
            try:
                run_rule = rules.get(RetentionKind.DETECTOR_RUNS.value)
                if run_rule and run_rule["enabled"]:
                    cutoff = (now - timedelta(days=run_rule["retention_days"])).isoformat()
                    expired = [row[0] for row in conn.execute(
                        "SELECT detector_run_id FROM detector_runs WHERE started_at < ?",
                        (cutoff,),
                    ).fetchall()]
                    if expired:
                        marks = ",".join("?" * len(expired))
                        conn.execute(
                            f"DELETE FROM detector_run_findings WHERE detector_run_id IN ({marks})",
                            expired,
                        )
                        # originating run 过期但仍在别处被引用的 Finding 要留下，
                        # 只把来源置空；真正孤立的才删。
                        conn.execute(
                            f"UPDATE findings SET detector_run_id = NULL"
                            f" WHERE detector_run_id IN ({marks})",
                            expired,
                        )
                        cursor = conn.execute(
                            "DELETE FROM findings WHERE finding_id NOT IN"
                            " (SELECT finding_id FROM detector_run_findings)"
                            " AND (detector_run_id IS NULL)",
                        )
                        counts[RetentionKind.DETECTOR_RUNS.value] = cursor.rowcount
                        conn.execute(
                            f"DELETE FROM raw_reports WHERE detector_run_id IN ({marks})",
                            expired,
                        )
                        cursor = conn.execute(
                            f"DELETE FROM detector_runs WHERE detector_run_id IN ({marks})",
                            expired,
                        )
                        counts[RetentionKind.DETECTOR_RUNS.value] += cursor.rowcount

                raw_rule = rules.get(RetentionKind.RAW_REPORTS.value)
                if raw_rule and raw_rule["enabled"]:
                    cutoff = (now - timedelta(days=raw_rule["retention_days"])).isoformat()
                    cursor = conn.execute(
                        "DELETE FROM raw_reports WHERE created_at < ?", (cutoff,)
                    )
                    counts[RetentionKind.RAW_REPORTS.value] = cursor.rowcount

                audit_rule = rules.get(RetentionKind.AUDIT_EVENTS.value)
                if audit_rule and audit_rule["enabled"]:
                    cutoff = (now - timedelta(days=audit_rule["retention_days"])).isoformat()
                    cursor = conn.execute(
                        "DELETE FROM audit_events WHERE occurred_at < ?", (cutoff,)
                    )
                    counts[RetentionKind.AUDIT_EVENTS.value] = cursor.rowcount

                # Execution 过期时其 Intent/RuntimeEvent 一并消失：子观测脱离
                # 执行边界后无法解读。无归因的 RuntimeEvent（execution_id 为空）
                # 没有可依附的边界，由 RUNTIME_EVENTS 规则按 received_at 兜底。
                execution_rule = rules.get(RetentionKind.EXECUTIONS.value)
                if execution_rule and execution_rule["enabled"]:
                    cutoff = (now - timedelta(days=execution_rule["retention_days"])).isoformat()
                    conn.execute(
                        "DELETE FROM runtime_events WHERE execution_id IN"
                        " (SELECT execution_id FROM executions WHERE started_at < ?)",
                        (cutoff,),
                    )
                    conn.execute(
                        "DELETE FROM intents WHERE execution_id IN"
                        " (SELECT execution_id FROM executions WHERE started_at < ?)",
                        (cutoff,),
                    )
                    cursor = conn.execute(
                        "DELETE FROM executions WHERE started_at < ?", (cutoff,)
                    )
                    counts[RetentionKind.EXECUTIONS.value] = cursor.rowcount

                event_rule = rules.get(RetentionKind.RUNTIME_EVENTS.value)
                if event_rule and event_rule["enabled"]:
                    cutoff = (now - timedelta(days=event_rule["retention_days"])).isoformat()
                    cursor = conn.execute(
                        "DELETE FROM runtime_events WHERE received_at < ?", (cutoff,)
                    )
                    counts[RetentionKind.RUNTIME_EVENTS.value] = cursor.rowcount

                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
        return counts


def retention_rule_from_row(row: dict[str, Any]) -> RetentionRule:
    return RetentionRule(
        data_kind=RetentionKind(row["data_kind"]),
        retention_days=row["retention_days"],
        enabled=bool(row["enabled"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
    )


class DeviceIdentityRepository:
    """设备身份。只证明一台端点有资格上报，不授予控制台用户权限。"""

    def __init__(self, storage: Storage) -> None:
        self._storage = storage

    def enroll(self, *, label: str) -> tuple[str, str]:
        """返回 (device_id, 明文令牌)。令牌只在创建时返回一次。"""
        device_id = f"dev_{uuid.uuid4().hex[:16]}"
        token = secrets.token_urlsafe(32)
        with self._storage._lock, self._storage.connection() as conn:
            conn.execute(
                "INSERT INTO device_identities (device_id, label, credential_hash, status,"
                " enrolled_at) VALUES (?,?,?,?,?)",
                (device_id, label, hash_token(token), DeviceStatus.ACTIVE.value, now_iso()),
            )
        return device_id, token

    def resolve(self, token: str) -> dict[str, Any] | None:
        with self._storage.connection() as conn:
            row = conn.execute(
                "SELECT * FROM device_identities WHERE credential_hash = ?",
                (hash_token(token),),
            ).fetchone()
        return dict(row) if row else None

    def list(self) -> list[dict[str, Any]]:
        with self._storage.connection() as conn:
            rows = conn.execute(
                "SELECT device_id, label, status, enrolled_at, last_seen_at, host_id, credential_rotated_at"
                " FROM device_identities ORDER BY enrolled_at"
            ).fetchall()
        return [dict(row) for row in rows]

    def get(self, device_id: str) -> dict[str, Any] | None:
        return next((row for row in self.list() if row["device_id"] == device_id), None)

    def set_host(self, *, device_id: str, host_id: str) -> None:
        with self._storage._lock, self._storage.connection() as conn:
            row = conn.execute("SELECT host_id FROM device_identities WHERE device_id=?", (device_id,)).fetchone()
            if row is None:
                raise ValueError("unknown_device")
            if row["host_id"] and row["host_id"] != host_id:
                raise ValueError("host_binding_immutable: enroll a new device")
            conn.execute("UPDATE device_identities SET host_id=? WHERE device_id=?", (host_id, device_id))

    def rotate_credential(self, *, device_id: str) -> str:
        token = secrets.token_urlsafe(32)
        with self._storage._lock, self._storage.connection() as conn:
            cursor = conn.execute(
                "UPDATE device_identities SET credential_hash=?, credential_rotated_at=? WHERE device_id=?",
                (hash_token(token), now_iso(), device_id),
            )
            if not cursor.rowcount:
                raise ValueError("unknown_device")
        return token

    def set_status(self, *, device_id: str, status: DeviceStatus) -> None:
        with self._storage._lock, self._storage.connection() as conn:
            conn.execute(
                "UPDATE device_identities SET status = ? WHERE device_id = ?",
                (status.value, device_id),
            )

    def touch(self, *, device_id: str) -> None:
        with self._storage._lock, self._storage.connection() as conn:
            conn.execute(
                "UPDATE device_identities SET last_seen_at = ? WHERE device_id = ?",
                (now_iso(), device_id),
            )


def device_identity_from_row(row: dict[str, Any]) -> DeviceIdentity:
    return DeviceIdentity(
        device_id=row["device_id"],
        label=row["label"],
        status=DeviceStatus(row["status"]),
        enrolled_at=datetime.fromisoformat(row["enrolled_at"]),
        last_seen_at=_parse_iso(row["last_seen_at"]),
    )
