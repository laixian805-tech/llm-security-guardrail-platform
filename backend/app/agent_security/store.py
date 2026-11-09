from __future__ import annotations

from datetime import datetime, timezone
import json
import hashlib
import os
import sqlite3
from pathlib import Path
from typing import Any

from .paths import agentsec_dir
from .assessment import provenance_for_path, score_findings
from .asset_identity import (classify_carrier, derive_ids, enrich_asset,
                             infer_product, legacy_provenance, state_for_carrier)
from .models import (
    AssetCarrier,
    AssetKind,
    AssetRecord,
    AssetState,
    ActivationState,
    DeviceRecord,
    InstallationState,
    RiskAssessment,
    EventSource,
    EventType,
    PolicyRule,
    ScanReport,
    SecurityAction,
    SecurityEvent,
    Severity,
    RuntimeState,
    utc_now_iso,
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  event_id TEXT PRIMARY KEY,
  ts TEXT NOT NULL,
  source TEXT NOT NULL,
  event_type TEXT NOT NULL,
  host TEXT,
  host_role TEXT,
  session_id TEXT,
  agent_name TEXT,
  agent_pid INTEGER,
  tool_name TEXT,
  tool_server TEXT,
  target_kind TEXT,
  target_path TEXT,
  dst_domain TEXT,
  dst_port INTEGER,
  action TEXT,
  rule_ids TEXT,
  severity TEXT,
  ti_verdict TEXT,
  ti_provider TEXT NOT NULL DEFAULT '',
  ti_confidence REAL NOT NULL DEFAULT 0,
  evidence TEXT,
  uploaded INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
CREATE INDEX IF NOT EXISTS idx_events_host_sev ON events(host, severity);

CREATE TABLE IF NOT EXISTS sessions (
  session_id TEXT PRIMARY KEY,
  host TEXT,
  agent_name TEXT,
  agent_version TEXT,
  user TEXT,
  cwd TEXT,
  started_at TEXT,
  ended_at TEXT
);

CREATE TABLE IF NOT EXISTS assets (
  asset_id TEXT PRIMARY KEY,
  kind TEXT,
  name TEXT,
  version TEXT,
  path TEXT,
  sha256 TEXT,
  host TEXT,
  owner TEXT NOT NULL DEFAULT '',
  source TEXT,
  provenance TEXT NOT NULL DEFAULT 'unknown',
  risk_assessment TEXT NOT NULL DEFAULT 'unassessed',
  risk_score REAL NOT NULL DEFAULT 0,
  ranking_score REAL NOT NULL DEFAULT 0,
  risk_breakdown TEXT NOT NULL DEFAULT '[]',
  finding_rule_ids TEXT NOT NULL DEFAULT '[]',
  ti_provider TEXT NOT NULL DEFAULT '',
  ti_verdict TEXT NOT NULL DEFAULT 'unknown',
  ti_confidence REAL NOT NULL DEFAULT 0,
  product TEXT NOT NULL DEFAULT '',
  publisher TEXT NOT NULL DEFAULT 'unknown',
  namespace TEXT NOT NULL DEFAULT 'unknown',
  release_id TEXT NOT NULL DEFAULT '',
  signature TEXT NOT NULL DEFAULT '',
  source_uri TEXT NOT NULL DEFAULT '',
  unknown_reason TEXT NOT NULL DEFAULT '',
  execution_origin TEXT NOT NULL DEFAULT '{}',
  logical_id TEXT NOT NULL DEFAULT '',
  instance_id TEXT NOT NULL DEFAULT '',
  content_hash TEXT NOT NULL DEFAULT '',
  carrier TEXT NOT NULL DEFAULT 'unknown',
  state TEXT NOT NULL DEFAULT 'discovered',
  installation_state TEXT NOT NULL DEFAULT 'cached',
  activation_state TEXT NOT NULL DEFAULT 'disabled',
  runtime_state TEXT NOT NULL DEFAULT 'idle',
  scope TEXT NOT NULL DEFAULT 'host',
  last_used_at TEXT NOT NULL DEFAULT '',
  removed_at TEXT NOT NULL DEFAULT '',
  registered INTEGER,
  first_seen TEXT,
  last_seen TEXT
);
CREATE INDEX IF NOT EXISTS idx_assets_kind ON assets(kind, name);

CREATE TABLE IF NOT EXISTS asset_reviews (
  asset_id TEXT PRIMARY KEY,
  risk_assessment TEXT NOT NULL,
  reviewer TEXT NOT NULL,
  reason TEXT NOT NULL,
  reviewed_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS asset_releases (
  release_id TEXT PRIMARY KEY,
  logical_id TEXT NOT NULL,
  version TEXT NOT NULL DEFAULT '',
  publisher TEXT NOT NULL DEFAULT 'unknown',
  namespace TEXT NOT NULL DEFAULT 'unknown',
  content_hash TEXT NOT NULL,
  signature TEXT NOT NULL DEFAULT '',
  source_uri TEXT NOT NULL DEFAULT '',
  released_at TEXT NOT NULL DEFAULT '',
  revoked_at TEXT NOT NULL DEFAULT '',
  resolution_status TEXT NOT NULL DEFAULT 'resolved'
);

CREATE TABLE IF NOT EXISTS asset_dependencies (
  dependency_id INTEGER PRIMARY KEY AUTOINCREMENT,
  parent_instance_id TEXT NOT NULL,
  dependency_type TEXT NOT NULL,
  package_name TEXT NOT NULL,
  requested_version TEXT NOT NULL DEFAULT '',
  resolved_version TEXT NOT NULL DEFAULT '',
  resolved_hash TEXT NOT NULL DEFAULT '',
  source_uri TEXT NOT NULL DEFAULT '',
  resolution_status TEXT NOT NULL DEFAULT 'unknown'
);

CREATE TABLE IF NOT EXISTS devices (
  device_id TEXT PRIMARY KEY,
  hostname TEXT NOT NULL,
  owner TEXT NOT NULL DEFAULT '',
  host_role TEXT,
  platform TEXT,
  token_sha256 TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL,
  last_seen TEXT,
  token_revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_devices_hostname ON devices(hostname);

CREATE TABLE IF NOT EXISTS scans (
  scan_id TEXT PRIMARY KEY,
  ts TEXT,
  host TEXT,
  target_kind TEXT,
  target_name TEXT,
  target_path TEXT,
  sha256 TEXT,
  verdict TEXT,
  findings TEXT,
  risk_assessment TEXT NOT NULL DEFAULT 'unassessed',
  risk_score REAL NOT NULL DEFAULT 0,
  ranking_score REAL NOT NULL DEFAULT 0,
  risk_breakdown TEXT NOT NULL DEFAULT '[]',
  assessment_reason TEXT NOT NULL DEFAULT '',
  ti_provider TEXT NOT NULL DEFAULT '',
  ti_verdict TEXT NOT NULL DEFAULT 'unknown',
  ti_confidence REAL NOT NULL DEFAULT 0
  ,product TEXT NOT NULL DEFAULT ''
  ,logical_id TEXT NOT NULL DEFAULT ''
  ,instance_id TEXT NOT NULL DEFAULT ''
  ,content_hash TEXT NOT NULL DEFAULT ''
  ,carrier TEXT NOT NULL DEFAULT 'unknown'
  ,state TEXT NOT NULL DEFAULT 'discovered'
  ,scope TEXT NOT NULL DEFAULT 'host'
  ,inventory_only INTEGER NOT NULL DEFAULT 0
  ,ti_iocs TEXT NOT NULL DEFAULT '[]'
  ,execution_origin TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_scans_ts ON scans(ts);

CREATE TABLE IF NOT EXISTS policies (
  policy_id TEXT PRIMARY KEY,
  name TEXT,
  kind TEXT,
  pattern TEXT,
  severity TEXT,
  action TEXT,
  enabled INTEGER,
  updated_at TEXT,
  note TEXT
);

CREATE TABLE IF NOT EXISTS collector_state (
  key TEXT PRIMARY KEY,
  value TEXT,
  updated_at TEXT
);

CREATE TABLE IF NOT EXISTS ioc_cache (
  ioc TEXT PRIMARY KEY,
  ioc_type TEXT,
  verdict TEXT,
  confidence REAL,
  provider TEXT,
  fetched_at TEXT,
  expires_at TEXT
);

CREATE TABLE IF NOT EXISTS ioc_queries (
  query_id INTEGER PRIMARY KEY AUTOINCREMENT,
  ioc TEXT NOT NULL,
  ioc_type TEXT NOT NULL,
  provider TEXT NOT NULL,
  queried_at TEXT NOT NULL,
  verdict TEXT NOT NULL,
  confidence REAL NOT NULL DEFAULT 0,
  cached INTEGER NOT NULL DEFAULT 0,
  reason TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS runtime_enforcements (
  enforcement_id TEXT PRIMARY KEY,
  event_id TEXT NOT NULL,
  requested_action TEXT NOT NULL,
  actual_action TEXT NOT NULL,
  product_ack INTEGER NOT NULL DEFAULT 0,
  exit_code INTEGER,
  enforcement_result TEXT NOT NULL DEFAULT 'unknown',
  adapter_version TEXT NOT NULL DEFAULT '',
  ts TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admission_decisions (
  decision_id TEXT PRIMARY KEY,
  logical_id TEXT NOT NULL DEFAULT '',
  release_id TEXT NOT NULL DEFAULT '',
  instance_id TEXT NOT NULL DEFAULT '',
  content_hash TEXT NOT NULL DEFAULT '',
  requested_state TEXT NOT NULL DEFAULT 'installed',
  action TEXT NOT NULL,
  policy_version TEXT NOT NULL DEFAULT '',
  checks_json TEXT NOT NULL DEFAULT '[]',
  reason TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL DEFAULT '',
  committed_at TEXT NOT NULL DEFAULT '',
  rolled_back_at TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS admission_approvals (
  approval_id TEXT PRIMARY KEY,
  decision_id TEXT NOT NULL,
  reviewer TEXT NOT NULL,
  action TEXT NOT NULL,
  scope TEXT NOT NULL DEFAULT 'host',
  reason TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS admission_commits (
  commit_id TEXT PRIMARY KEY,
  decision_id TEXT NOT NULL,
  idempotency_key TEXT NOT NULL UNIQUE,
  product TEXT NOT NULL DEFAULT '',
  version TEXT NOT NULL DEFAULT '',
  config_path TEXT NOT NULL DEFAULT '',
  before_hash TEXT NOT NULL DEFAULT '',
  after_hash TEXT NOT NULL DEFAULT '',
  product_feedback TEXT NOT NULL DEFAULT '',
  result TEXT NOT NULL,
  error TEXT NOT NULL DEFAULT '',
  ts TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ioc_queries_time ON ioc_queries(queried_at DESC);
CREATE INDEX IF NOT EXISTS idx_ioc_queries_ioc ON ioc_queries(ioc, ioc_type);
"""


def _marketplace_plugin_name(path: str) -> str:
    parts = Path(path).parts
    lowered = [part.lower() for part in parts]
    for index in range(len(lowered) - 2):
        if lowered[index:index + 3] == [".tmp", "plugins", "plugins"]:
            return parts[index + 3] if index + 3 < len(parts) else "unknown"
    return "unknown"


def _marketplace_repository_path(path: str) -> str:
    parts = Path(path).parts
    lowered = [part.lower() for part in parts]
    for index in range(len(lowered) - 2):
        if lowered[index:index + 3] == [".tmp", "plugins", "plugins"]:
            return str(Path(*parts[:min(index + 3, len(parts))]))
    return str(Path(path).parent)


def default_db_path() -> Path:
    """Resolve the local database path without importing platform settings.

    Edge devices and the platform share this module; the platform passes an
    explicit path built from its own settings (LLMSEC_AGENTSEC_DB_PATH).
    """
    import os

    env = os.environ.get("AGENTSEC_DB_PATH")
    if env:
        return Path(env)
    return agentsec_dir() / "agentsec.db"


class AgentSecStore:
    """SQLite persistence for events, sessions, assets, scans and policies."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = Path(db_path) if db_path else default_db_path()
        self.db_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._secure_path(self.db_path.parent, 0o700)
        self._init_db()

    @staticmethod
    def _secure_path(path: Path, mode: int) -> None:
        if os.name != "nt":
            try:
                path.chmod(mode)
            except OSError:
                pass

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        self._secure_path(self.db_path, 0o600)
        self._secure_path(Path(str(self.db_path) + "-wal"), 0o600)
        self._secure_path(Path(str(self.db_path) + "-shm"), 0o600)
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            asset_columns = {row["name"] for row in
                             conn.execute("PRAGMA table_info(assets)").fetchall()}
            if "owner" not in asset_columns:
                conn.execute("ALTER TABLE assets ADD COLUMN owner TEXT NOT NULL DEFAULT ''")
            for column, declaration in (
                ("provenance", "TEXT NOT NULL DEFAULT 'unknown'"),
                ("risk_assessment", "TEXT NOT NULL DEFAULT 'unassessed'"),
                ("risk_score", "REAL NOT NULL DEFAULT 0"),
                ("ranking_score", "REAL NOT NULL DEFAULT 0"),
                ("risk_breakdown", "TEXT NOT NULL DEFAULT '[]'"),
                ("finding_rule_ids", "TEXT NOT NULL DEFAULT '[]'"),
                ("ti_provider", "TEXT NOT NULL DEFAULT ''"),
                ("ti_verdict", "TEXT NOT NULL DEFAULT 'unknown'"),
                ("ti_confidence", "REAL NOT NULL DEFAULT 0"),
                ("product", "TEXT NOT NULL DEFAULT ''"),
                ("publisher", "TEXT NOT NULL DEFAULT 'unknown'"),
                ("namespace", "TEXT NOT NULL DEFAULT 'unknown'"),
                ("release_id", "TEXT NOT NULL DEFAULT ''"),
                ("signature", "TEXT NOT NULL DEFAULT ''"),
                ("source_uri", "TEXT NOT NULL DEFAULT ''"),
                ("unknown_reason", "TEXT NOT NULL DEFAULT ''"),
                ("execution_origin", "TEXT NOT NULL DEFAULT '{}'"),
                ("logical_id", "TEXT NOT NULL DEFAULT ''"),
                ("instance_id", "TEXT NOT NULL DEFAULT ''"),
                ("content_hash", "TEXT NOT NULL DEFAULT ''"),
                ("carrier", "TEXT NOT NULL DEFAULT 'unknown'"),
                ("state", "TEXT NOT NULL DEFAULT 'discovered'"),
                ("installation_state", "TEXT NOT NULL DEFAULT 'cached'"),
                ("activation_state", "TEXT NOT NULL DEFAULT 'disabled'"),
                ("runtime_state", "TEXT NOT NULL DEFAULT 'idle'"),
                ("scope", "TEXT NOT NULL DEFAULT 'host'"),
                ("last_used_at", "TEXT NOT NULL DEFAULT ''"),
                ("removed_at", "TEXT NOT NULL DEFAULT ''"),
            ):
                if column not in asset_columns:
                    conn.execute(f"ALTER TABLE assets ADD COLUMN {column} {declaration}")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_logical ON assets(logical_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_state ON assets(state, carrier)")
            for row in conn.execute(
                "SELECT asset_id,kind,name,path,host,sha256,provenance,carrier,state,product"
                " FROM assets WHERE logical_id='' OR instance_id='' OR carrier='unknown'"
            ).fetchall():
                carrier = classify_carrier(row["path"] or "")
                product = infer_product(row["path"] or "", row["product"] or "")
                logical_id, instance_id = derive_ids(
                    product=product, kind=row["kind"] or "unknown",
                    name=row["name"] or "", host=row["host"] or "",
                    carrier=carrier, path=row["path"] or "",
                )
                # Historical rows lack enablement evidence. Preserve a cache
                # classification, but leave every other state undiscovered.
                state = (AssetState.CACHED if carrier == AssetCarrier.MARKETPLACE_CACHE
                         else AssetState.DISCOVERED)
                provenance = (row["provenance"] if row["provenance"] != "unknown"
                              else legacy_provenance(carrier))
                conn.execute(
                    "UPDATE assets SET product=?,logical_id=?,instance_id=?,content_hash=?,"
                    "carrier=?,state=?,provenance=? WHERE asset_id=?",
                    (product, logical_id, instance_id, row["sha256"] or "", carrier.value,
                     state.value, provenance, row["asset_id"]),
                )
            device_columns = {row["name"] for row in
                              conn.execute("PRAGMA table_info(devices)").fetchall()}
            if "owner" not in device_columns:
                conn.execute("ALTER TABLE devices ADD COLUMN owner TEXT NOT NULL DEFAULT ''")
            if "token_revoked_at" not in device_columns:
                conn.execute("ALTER TABLE devices ADD COLUMN token_revoked_at TEXT")
            event_columns = {row["name"] for row in
                             conn.execute("PRAGMA table_info(events)").fetchall()}
            for column, declaration in (("ti_provider", "TEXT NOT NULL DEFAULT ''"),
                                        ("ti_confidence", "REAL NOT NULL DEFAULT 0")):
                if column not in event_columns:
                    conn.execute(f"ALTER TABLE events ADD COLUMN {column} {declaration}")
            scan_columns = {row["name"] for row in
                            conn.execute("PRAGMA table_info(scans)").fetchall()}
            for column, declaration in (
                ("risk_assessment", "TEXT NOT NULL DEFAULT 'unassessed'"),
                ("risk_score", "REAL NOT NULL DEFAULT 0"),
                ("ranking_score", "REAL NOT NULL DEFAULT 0"),
                ("risk_breakdown", "TEXT NOT NULL DEFAULT '[]'"),
                ("assessment_reason", "TEXT NOT NULL DEFAULT ''"),
                ("ti_provider", "TEXT NOT NULL DEFAULT ''"),
                ("ti_verdict", "TEXT NOT NULL DEFAULT 'unknown'"),
                ("ti_confidence", "REAL NOT NULL DEFAULT 0"),
            ):
                if column not in scan_columns:
                    conn.execute(f"ALTER TABLE scans ADD COLUMN {column} {declaration}")
            for column, declaration in (
                ("product", "TEXT NOT NULL DEFAULT ''"),
                ("logical_id", "TEXT NOT NULL DEFAULT ''"),
                ("instance_id", "TEXT NOT NULL DEFAULT ''"),
                ("content_hash", "TEXT NOT NULL DEFAULT ''"),
                ("carrier", "TEXT NOT NULL DEFAULT 'unknown'"),
                ("state", "TEXT NOT NULL DEFAULT 'discovered'"),
                ("scope", "TEXT NOT NULL DEFAULT 'host'"),
                ("inventory_only", "INTEGER NOT NULL DEFAULT 0"),
                ("ti_iocs", "TEXT NOT NULL DEFAULT '[]'"),
                ("execution_origin", "TEXT NOT NULL DEFAULT '{}'"),
            ):
                if column not in scan_columns:
                    conn.execute(f"ALTER TABLE scans ADD COLUMN {column} {declaration}")

    # ---------- events ----------

    def insert_event(self, event: SecurityEvent) -> bool:
        """Insert one event; returns False when the event_id already exists."""
        return self.insert_events([event]) == 1

    def insert_events(self, events: list[SecurityEvent]) -> int:
        if not events:
            return 0
        accepted = 0
        with self._connect() as conn:
            for event in events:
                cur = conn.execute(
                    "INSERT OR IGNORE INTO events (event_id, ts, source, event_type, host, host_role,"
                    " session_id, agent_name, agent_pid, tool_name, tool_server, target_kind, target_path,"
                    " dst_domain, dst_port, action, rule_ids, severity, ti_verdict, ti_provider,"
                    " ti_confidence, evidence, uploaded)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,0)",
                    (
                        event.event_id,
                        event.ts,
                        event.source.value,
                        event.event_type.value,
                        event.host,
                        event.host_role,
                        event.session_id,
                        event.agent_name,
                        event.agent_pid,
                        event.tool_name,
                        event.tool_server,
                        event.target_kind,
                        event.target_path,
                        event.dst_domain,
                        event.dst_port,
                        event.action.value,
                        json.dumps(event.rule_ids),
                        event.severity.value,
                        event.ti_verdict,
                        event.ti_provider,
                        event.ti_confidence,
                        json.dumps(event.evidence, ensure_ascii=False),
                    ),
                )
                accepted += cur.rowcount if cur.rowcount > 0 else 0
        return accepted

    def list_events(
        self,
        *,
        host: str | None = None,
        severity: str | None = None,
        rule_id: str | None = None,
        source: str | None = None,
        event_type: str | None = None,
        session_id: str | None = None,
        action: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 200,
    ) -> list[SecurityEvent]:
        clauses: list[str] = []
        params: list[Any] = []
        if host:
            clauses.append("host = ?")
            params.append(host)
        if action:
            clauses.append("action = ?")
            params.append(action)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if rule_id:
            clauses.append("rule_ids LIKE ?")
            params.append(f'%"{rule_id}"%')
        if source:
            clauses.append("source = ?")
            params.append(source)
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        if session_id:
            clauses.append("session_id = ?")
            params.append(session_id)
        if since:
            clauses.append("ts >= ?")
            params.append(since)
        if until:
            clauses.append("ts <= ?")
            params.append(until)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM events{where} ORDER BY ts DESC LIMIT ?", params
            ).fetchall()
        return [self._row_to_event(row) for row in rows]

    def existing_event_ids(self, event_ids: list[str]) -> set[str]:
        """Subset of ``event_ids`` already stored; used for upload dedupe."""
        if not event_ids:
            return set()
        found: set[str] = set()
        with self._connect() as conn:
            for start in range(0, len(event_ids), 400):
                chunk = event_ids[start:start + 400]
                placeholders = ",".join("?" for _ in chunk)
                rows = conn.execute(
                    f"SELECT event_id FROM events WHERE event_id IN ({placeholders})",
                    chunk,
                ).fetchall()
                found.update(row["event_id"] for row in rows)
        return found

    def get_event(self, event_id: str) -> SecurityEvent | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM events WHERE event_id = ?", (event_id,)).fetchone()
        return self._row_to_event(row) if row is not None else None

    def update_event_ti(self, event_id: str, *, verdict: str, provider: str,
                        confidence: float, ioc_type: str, cached: bool) -> bool:
        with self._connect() as conn:
            row = conn.execute("SELECT evidence FROM events WHERE event_id = ?",
                               (event_id,)).fetchone()
            if row is None:
                return False
            try:
                evidence = json.loads(row["evidence"] or "{}")
            except json.JSONDecodeError:
                evidence = {}
            evidence["ti_shadow"] = {"ioc_type": ioc_type, "verdict": verdict,
                                     "confidence": confidence, "cached": cached}
            conn.execute(
                "UPDATE events SET ti_verdict=?, ti_provider=?, ti_confidence=?, evidence=? WHERE event_id=?",
                (verdict, provider, confidence, json.dumps(evidence, ensure_ascii=False), event_id),
            )
        return True

    def update_scan_ti(self, scan_id: str, *, verdict: str, provider: str,
                       confidence: float) -> bool:
        with self._connect() as conn:
            row = conn.execute("SELECT findings FROM scans WHERE scan_id=?",
                               (scan_id,)).fetchone()
            if row is None:
                return False
            conn.execute(
                "UPDATE scans SET ti_provider=?,ti_verdict=?,ti_confidence=? WHERE scan_id=?",
                (provider, verdict, confidence, scan_id),
            )
        return True

    def pending_events(self, limit: int = 500) -> list[SecurityEvent]:
        """Events recorded locally by an edge collector and not yet uploaded."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM events WHERE uploaded = 0 ORDER BY ts ASC LIMIT ?", (limit,)
            ).fetchall()
        return [self._row_to_event(row) for row in rows]

    def pending_event_stats(self) -> dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS pending_events, MIN(ts) AS oldest_ts"
                " FROM events WHERE uploaded = 0"
            ).fetchone()
        oldest_age = None
        if row["oldest_ts"]:
            try:
                oldest = datetime.fromisoformat(row["oldest_ts"].replace("Z", "+00:00"))
                oldest_age = max(0, int((datetime.now(timezone.utc) - oldest).total_seconds()))
            except ValueError:
                pass
        return {"pending_events": int(row["pending_events"]),
                "oldest_pending_age_seconds": oldest_age}

    def mark_uploaded(self, event_ids: list[str]) -> None:
        if not event_ids:
            return
        placeholders = ",".join("?" for _ in event_ids)
        with self._connect() as conn:
            conn.execute(
                f"UPDATE events SET uploaded = 1 WHERE event_id IN ({placeholders})", event_ids
            )

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> SecurityEvent:
        return SecurityEvent(
            event_id=row["event_id"],
            ts=row["ts"],
            source=EventSource(row["source"]),
            event_type=EventType(row["event_type"]),
            host=row["host"] or "",
            host_role=row["host_role"] or "",
            session_id=row["session_id"] or "",
            agent_name=row["agent_name"] or "",
            agent_pid=row["agent_pid"],
            tool_name=row["tool_name"] or "",
            tool_server=row["tool_server"] or "",
            target_kind=row["target_kind"] or "",
            target_path=row["target_path"] or "",
            dst_domain=row["dst_domain"] or "",
            dst_port=row["dst_port"],
            action=SecurityAction(row["action"]),
            rule_ids=json.loads(row["rule_ids"] or "[]"),
            severity=Severity(row["severity"]),
            ti_verdict=row["ti_verdict"] or "unknown",
            ti_provider=row["ti_provider"] or "",
            ti_confidence=float(row["ti_confidence"] or 0),
            evidence=json.loads(row["evidence"] or "{}"),
        )

    # ---------- collector state (audit cursor, heartbeat, upload backoff) ----------

    def get_state(self, key: str, default: str | None = None) -> str | None:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value FROM collector_state WHERE key = ?", (key,)
            ).fetchone()
        return row["value"] if row else default

    def set_state(self, key: str, value: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO collector_state (key, value, updated_at) VALUES (?,?,?)"
                " ON CONFLICT(key) DO UPDATE SET value = excluded.value,"
                " updated_at = excluded.updated_at",
                (key, value, utc_now_iso()),
            )

    def reserve_daily_budget(self, key: str, *, limit: int) -> bool:
        """Atomically reserve one daily external IOC lookup."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value FROM collector_state WHERE key = ?", (key,)
            ).fetchone()
            used = int(row["value"]) if row else 0
            if used >= limit:
                return False
            conn.execute(
                "INSERT INTO collector_state (key,value,updated_at) VALUES (?,?,?)"
                " ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                (key, str(used + 1), utc_now_iso()),
            )
            return True

    def list_monitor_reads(self, *, now_epoch: float,
                           window_seconds: float) -> dict[str, list[tuple[float, str]]]:
        """Load R005 sensitive reads retained across collector cycles."""
        cutoff = now_epoch - window_seconds
        raw = self.get_state("monitor_sensitive_reads", "[]") or "[]"
        try:
            payload = json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            payload = []
        result: dict[str, list[tuple[float, str]]] = {}
        for item in payload if isinstance(payload, list) else []:
            if not isinstance(item, dict):
                continue
            try:
                epoch = float(item["epoch"])
                session_id = str(item["session_id"])
                path = str(item["path"])
            except (KeyError, TypeError, ValueError):
                continue
            if epoch >= cutoff and session_id and path:
                result.setdefault(session_id, []).append((epoch, path))
        return result

    def save_monitor_reads(self, reads: dict[str, list[tuple[float, str]]],
                           *, now_epoch: float, window_seconds: float) -> None:
        cutoff = now_epoch - window_seconds
        payload = [
            {"session_id": session_id, "epoch": epoch, "path": path}
            for session_id, entries in reads.items()
            for epoch, path in entries
            if epoch >= cutoff
        ]
        self.set_state("monitor_sensitive_reads", json.dumps(payload, ensure_ascii=False))

    # ---------- sessions ----------

    def upsert_session(
        self,
        session_id: str,
        *,
        host: str = "",
        agent_name: str = "",
        agent_version: str = "",
        user: str = "",
        cwd: str = "",
        ended: bool = False,
    ) -> None:
        now = utc_now_iso()
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT started_at FROM sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
            if existing is None:
                conn.execute(
                    "INSERT INTO sessions (session_id, host, agent_name, agent_version, user, cwd,"
                    " started_at, ended_at) VALUES (?,?,?,?,?,?,?,?)",
                    (session_id, host, agent_name, agent_version, user, cwd, now,
                     now if ended else None),
                )
                return
            conn.execute(
                "UPDATE sessions SET host = COALESCE(NULLIF(?, ''), host),"
                " agent_name = COALESCE(NULLIF(?, ''), agent_name),"
                " agent_version = COALESCE(NULLIF(?, ''), agent_version),"
                " user = COALESCE(NULLIF(?, ''), user),"
                " cwd = COALESCE(NULLIF(?, ''), cwd),"
                " ended_at = COALESCE(ended_at, ?) WHERE session_id = ?",
                (host, agent_name, agent_version, user, cwd,
                 now if ended else None, session_id),
            )

    def list_sessions(self, *, host: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        """Sessions for the SOC view.

        Registered sessions (hook/proc-backfill rows) take precedence; sessions
        that only exist in events (e.g. monitor orphan sessions) are derived
        from the event stream so they still show up in the UI.
        """
        clauses = ""
        params: list[Any] = []
        if host:
            clauses = " WHERE a.host = ?"
            params.append(host)
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(
                "WITH event_agg AS ("
                "  SELECT session_id, COUNT(*) AS event_count,"
                "   SUM(CASE WHEN event_type = 'tool_call' THEN 1 ELSE 0 END) AS tool_calls,"
                "   SUM(CASE WHEN severity IN ('medium', 'high', 'critical') THEN 1 ELSE 0 END)"
                "     AS risk_events,"
                "   MAX(CASE severity WHEN 'critical' THEN 4 WHEN 'high' THEN 3"
                "       WHEN 'medium' THEN 2 WHEN 'low' THEN 1 ELSE 0 END) AS max_sev_rank,"
                "   MIN(ts) AS first_ts, MAX(ts) AS last_ts, MAX(host) AS host,"
                "   MAX(agent_name) AS agent_name"
                "   FROM events WHERE session_id != '' GROUP BY session_id"
                "), all_sessions AS ("
                "  SELECT session_id, host, agent_name, agent_version, user, cwd,"
                "         started_at, ended_at FROM sessions WHERE session_id != ''"
                "  UNION ALL"
                "  SELECT session_id, host, agent_name, '', '', '', first_ts, NULL"
                "    FROM event_agg"
                "   WHERE session_id NOT IN (SELECT session_id FROM sessions WHERE session_id != '')"
                ") "
                "SELECT a.session_id, a.host, a.agent_name, a.agent_version, a.user, a.cwd,"
                " a.started_at, a.ended_at,"
                " COALESCE(e.event_count, 0) AS event_count,"
                " COALESCE(e.tool_calls, 0) AS tool_calls,"
                " COALESCE(e.risk_events, 0) AS risk_events,"
                " COALESCE(e.max_sev_rank, 0) AS max_sev_rank,"
                " e.first_ts, e.last_ts"
                " FROM all_sessions a LEFT JOIN event_agg e ON e.session_id = a.session_id"
                f"{clauses} ORDER BY a.started_at DESC LIMIT ?",
                params,
            ).fetchall()
        severity_names = ["info", "low", "medium", "high", "critical"]
        result = []
        for row in rows:
            item = dict(row)
            item["max_severity"] = severity_names[item["max_sev_rank"] or 0]
            result.append(item)
        return result

    def session_detail(self, session_id: str) -> dict[str, Any]:
        events = self.list_events(session_id=session_id, limit=1000)
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
            ).fetchone()
        session = dict(row) if row else {"session_id": session_id}
        timeline = [
            {
                "ts": event.ts,
                "event_type": event.event_type.value,
                "action": event.action.value,
                "severity": event.severity.value,
                "rule_ids": event.rule_ids,
                "ti_verdict": event.ti_verdict,
                "ti_provider": event.ti_provider,
                "ti_confidence": event.ti_confidence,
                "tool_name": event.tool_name,
                "target_path": event.target_path,
                "dst_domain": event.dst_domain,
                "dst_port": event.dst_port,
                "agent_pid": event.agent_pid,
            }
            for event in events
        ]
        return {"session": session, "timeline": timeline}

    # ---------- assets ----------

    def upsert_asset(self, asset: AssetRecord) -> None:
        asset = enrich_asset(asset)
        now = utc_now_iso()
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT asset_id,first_seen,owner,source FROM assets"
                " WHERE instance_id = ? OR asset_id = ? ORDER BY CASE"
                " WHEN instance_id = ? THEN 0 ELSE 1 END LIMIT 1",
                (asset.instance_id, asset.asset_id, asset.instance_id),
            ).fetchone()
            if existing is None:
                conn.execute(
                    "INSERT INTO assets (asset_id, kind, name, version, path, sha256, host, owner,"
                    " source, provenance, risk_assessment, risk_score,ranking_score,risk_breakdown,"
                    " finding_rule_ids, ti_provider, ti_verdict,"
                    " ti_confidence, product,publisher,namespace,release_id,signature,source_uri,"
                    " unknown_reason,execution_origin,logical_id,instance_id,content_hash,carrier,state,"
                    " installation_state,activation_state,runtime_state,scope,last_used_at,removed_at,"
                    " registered, first_seen, last_seen)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (asset.asset_id or asset.instance_id, asset.kind.value, asset.name,
                     asset.version, asset.path,
                     asset.sha256, asset.host, asset.owner, asset.source,
                     asset.provenance, asset.risk_assessment.value, asset.risk_score,
                     asset.ranking_score,
                     json.dumps(asset.risk_breakdown, ensure_ascii=False),
                     json.dumps(asset.finding_rule_ids), asset.ti_provider, asset.ti_verdict,
                     asset.ti_confidence, asset.product, asset.publisher, asset.namespace,
                     asset.release_id, asset.signature, asset.source_uri, asset.unknown_reason,
                     json.dumps(asset.execution_origin, ensure_ascii=False), asset.logical_id,
                     asset.instance_id, asset.content_hash, asset.carrier.value, asset.state.value,
                     asset.installation_state.value, asset.activation_state.value,
                     asset.runtime_state.value, asset.scope,
                     asset.last_used_at, asset.removed_at, int(asset.registered), now, now),
                )
                return
            conn.execute(
                "UPDATE assets SET kind=?,name=?,version=?,path=?,sha256=?,host=?,"
                " owner = COALESCE(NULLIF(?, ''), owner),"
                " source = COALESCE(NULLIF(?, ''), source),"
                " provenance = COALESCE(NULLIF(?, 'unknown'), provenance),"
                " risk_assessment = CASE WHEN ? = 'unassessed' THEN risk_assessment ELSE ? END,"
                " risk_score = CASE WHEN ? = 'unassessed' THEN risk_score ELSE ? END,"
                " ranking_score = CASE WHEN ? = 'unassessed' THEN ranking_score ELSE ? END,"
                " risk_breakdown = CASE WHEN ? = 'unassessed' THEN risk_breakdown ELSE ? END,"
                " finding_rule_ids = CASE WHEN ? = '[]' THEN finding_rule_ids ELSE ? END,"
                " ti_provider = COALESCE(NULLIF(?, ''), ti_provider),"
                " ti_confidence = CASE WHEN ? = 0 THEN ti_confidence ELSE ? END,"
                " product=?,publisher=?,namespace=?,release_id=?,signature=?,source_uri=?,"
                " unknown_reason=?,execution_origin=?,logical_id=?,instance_id=?,content_hash=?,carrier=?,"
                " state=CASE WHEN state='active' AND ? NOT IN ('removed','disabled') THEN state ELSE ? END,"
                " installation_state=?,activation_state=?,runtime_state=?,scope=?,"
                " last_used_at=COALESCE(NULLIF(?,''),last_used_at),"
                " removed_at=?,"
                " registered = CASE WHEN ? = 1 THEN 1 ELSE registered END,"
                " last_seen = ? WHERE asset_id = ?",
                (asset.kind.value, asset.name, asset.version, asset.path, asset.sha256, asset.host,
                 asset.owner,
                 asset.source, asset.provenance, asset.risk_assessment.value,
                 asset.risk_assessment.value,
                 asset.risk_assessment.value, asset.risk_score,
                 asset.risk_assessment.value,
                 asset.ranking_score,
                 asset.risk_assessment.value,
                 json.dumps(asset.risk_breakdown, ensure_ascii=False),
                 json.dumps(asset.finding_rule_ids), json.dumps(asset.finding_rule_ids),
                 asset.ti_provider, asset.ti_verdict,
                 asset.ti_confidence,
                 asset.product, asset.publisher, asset.namespace, asset.release_id,
                 asset.signature, asset.source_uri, asset.unknown_reason,
                 json.dumps(asset.execution_origin, ensure_ascii=False), asset.logical_id,
                 asset.instance_id, asset.content_hash, asset.carrier.value,
                 asset.state.value, asset.state.value,
                 asset.installation_state.value, asset.activation_state.value,
                 asset.runtime_state.value, asset.scope,
                 asset.last_used_at, asset.removed_at, int(asset.registered), now,
                 existing["asset_id"]),
            )

    def list_assets(self, *, kind: str | None = None, host: str | None = None,
                    state: str | None = None, carrier: str | None = None,
                    logical_id: str | None = None) -> list[AssetRecord]:
        clauses: list[str] = []
        params: list[Any] = []
        if kind:
            clauses.append("kind = ?")
            params.append(kind)
        if host:
            clauses.append("host = ?")
            params.append(host)
        if state:
            clauses.append("state = ?")
            params.append(state)
        if carrier:
            clauses.append("carrier = ?")
            params.append(carrier)
        if logical_id:
            clauses.append("logical_id = ?")
            params.append(logical_id)
        where = f" WHERE {' AND '.join('a.' + clause for clause in clauses)}" if clauses else ""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT a.*,r.risk_assessment AS reviewed_risk_assessment,"
                " r.reviewer AS assessment_reviewer,r.reason AS assessment_reason,"
                " r.reviewed_at AS assessment_reviewed_at FROM assets a"
                " LEFT JOIN asset_reviews r ON r.asset_id=a.asset_id"
                f"{where} ORDER BY a.last_seen DESC", params
            ).fetchall()
        return [
            AssetRecord(
                asset_id=row["asset_id"],
                kind=AssetKind(row["kind"]),
                name=row["name"],
                version=row["version"] or "",
                path=row["path"] or "",
                sha256=row["sha256"] or "",
                host=row["host"] or "",
                owner=row["owner"] or "",
                source=row["source"] or "",
                provenance=row["provenance"] or "unknown",
                risk_assessment=RiskAssessment(row["reviewed_risk_assessment"]
                                               or row["risk_assessment"] or "unassessed"),
                risk_score=float(row["risk_score"] or 0),
                ranking_score=float(row["ranking_score"] or 0),
                risk_breakdown=json.loads(row["risk_breakdown"] or "[]"),
                finding_rule_ids=json.loads(row["finding_rule_ids"] or "[]"),
                assessment_reviewer=row["assessment_reviewer"] or "",
                assessment_reason=row["assessment_reason"] or "",
                assessment_reviewed_at=row["assessment_reviewed_at"] or "",
                ti_provider=row["ti_provider"] or "",
                ti_verdict=row["ti_verdict"] or "unknown",
                ti_confidence=float(row["ti_confidence"] or 0),
                product=row["product"] or "",
                publisher=row["publisher"] or "unknown",
                namespace=row["namespace"] or "unknown",
                release_id=row["release_id"] or "",
                signature=row["signature"] or "",
                source_uri=row["source_uri"] or "",
                unknown_reason=row["unknown_reason"] or "",
                execution_origin=json.loads(row["execution_origin"] or "{}"),
                logical_id=row["logical_id"] or "",
                instance_id=row["instance_id"] or "",
                content_hash=row["content_hash"] or row["sha256"] or "",
                carrier=AssetCarrier(row["carrier"] or "unknown"),
                state=AssetState(row["state"] or "discovered"),
                installation_state=InstallationState(row["installation_state"] or "cached"),
                activation_state=ActivationState(row["activation_state"] or "disabled"),
                runtime_state=RuntimeState(row["runtime_state"] or "idle"),
                scope=row["scope"] or "host",
                last_used_at=row["last_used_at"] or "",
                removed_at=row["removed_at"] or "",
                registered=bool(row["registered"]),
                first_seen=row["first_seen"] or "",
                last_seen=row["last_seen"] or "",
            )
            for row in rows
        ]

    def asset_summary(self, *, kind: str | None = None,
                      host: str | None = None) -> dict[str, Any]:
        assets = self.list_assets(kind=kind, host=host)
        count_ids: dict[str, dict[str, dict[str, set[str]]]] = {}
        instance_counts: dict[str, dict[str, dict[str, int]]] = {}
        provenance_ids: dict[str, dict[str, dict[str, set[str]]]] = {}
        logical_ids: dict[str, dict[str, set[str]]] = {}
        repositories: dict[tuple[str, str], dict[str, Any]] = {}
        for asset in assets:
            state = asset.state.value
            asset_kind = asset.kind.value
            carrier = asset.carrier.value
            provenance = asset.provenance or "unknown"
            logical_ids.setdefault(state, {}).setdefault(asset_kind, set()).add(
                asset.logical_id or asset.asset_id
            )
            if asset.carrier == AssetCarrier.MARKETPLACE_CACHE:
                repository_path = _marketplace_repository_path(asset.path)
                key = (asset.host, repository_path)
                repository = repositories.setdefault(key, {
                    "host": asset.host,
                    "path": repository_path,
                    "content_hashes": set(),
                    "instances": 0,
                    "plugins": set(),
                })
                repository["content_hashes"].add(asset.content_hash or asset.instance_id)
                repository["instances"] += 1
                repository["plugins"].add(_marketplace_plugin_name(asset.path))
            identity = asset.logical_id or asset.asset_id
            count_ids.setdefault(state, {}).setdefault(asset_kind, {}).setdefault(
                carrier, set()
            ).add(identity)
            instance_counts.setdefault(state, {}).setdefault(asset_kind, {})[carrier] = (
                instance_counts.setdefault(state, {}).setdefault(asset_kind, {}).get(carrier, 0) + 1
            )
            provenance_ids.setdefault(state, {}).setdefault(asset_kind, {}).setdefault(
                provenance, set()
            ).add(identity)

        counts = {
            state: {
                kind: {carrier: len(ids) for carrier, ids in carriers.items()}
                for kind, carriers in kinds.items()
            }
            for state, kinds in count_ids.items()
        }
        provenance_counts = {
            state: {
                kind: {provenance: len(ids) for provenance, ids in provenances.items()}
                for kind, provenances in kinds.items()
            }
            for state, kinds in provenance_ids.items()
        }

        state_totals = {
            state: sum(len(ids) for ids in kinds.values())
            for state, kinds in logical_ids.items()
        }
        real_logical_ids: dict[str, set[str]] = {}
        synthetic_logical_ids: set[str] = set()
        for asset in assets:
            identity = asset.logical_id or asset.asset_id
            if asset.carrier == AssetCarrier.SYNTHETIC:
                synthetic_logical_ids.add(identity)
            else:
                real_logical_ids.setdefault(asset.state.value, set()).add(identity)
        cache_repositories = [
            {"host": row["host"], "path": row["path"],
             "plugins": len(row["plugins"]),
             "definitions": len(row["content_hashes"]),
             "instances": row["instances"]}
            for row in repositories.values()
        ]
        cache_content_hashes = {
            content_hash
            for row in repositories.values()
            for content_hash in row["content_hashes"]
        }
        return {
            "counts": counts,
            "instance_counts": instance_counts,
            "by_state_kind_provenance": provenance_counts,
            "logical_assets_by_state": state_totals,
            "real_logical_assets_by_state": {
                state: len(ids) for state, ids in real_logical_ids.items()
            },
            "synthetic_logical_assets": len(synthetic_logical_ids),
            "instances": len(assets),
            "marketplace_cache": {
                "repositories": len(cache_repositories),
                "plugins": sum(row["plugins"] for row in cache_repositories),
                "definitions": len(cache_content_hashes),
                "instances": sum(row["instances"] for row in cache_repositories),
                "items": cache_repositories,
            },
            "default_states": ["installed", "enabled", "active"],
            "legacy_metrics": {
                "status": "obsolete_v1_path_count",
                "values": {"skills": 542, "targets": 599,
                           "block_verdicts": 125, "alert_verdicts": 459},
            },
        }

    def record_asset_review(self, asset_id: str, *, assessment: RiskAssessment,
                            reviewer: str, reason: str) -> AssetRecord | None:
        reviewed_at = utc_now_iso()
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM assets WHERE asset_id=?", (asset_id,)).fetchone()
            if row is None:
                return None
            conn.execute(
                "INSERT INTO asset_reviews(asset_id,risk_assessment,reviewer,reason,reviewed_at)"
                " VALUES(?,?,?,?,?) ON CONFLICT(asset_id) DO UPDATE SET"
                " risk_assessment=excluded.risk_assessment,reviewer=excluded.reviewer,"
                " reason=excluded.reason,reviewed_at=excluded.reviewed_at",
                (asset_id, assessment.value, reviewer, reason, reviewed_at),
            )
        return AssetRecord(
            asset_id=row["asset_id"], kind=AssetKind(row["kind"]), name=row["name"],
            version=row["version"] or "", path=row["path"] or "", sha256=row["sha256"] or "",
            host=row["host"] or "", owner=row["owner"] or "", source=row["source"] or "",
            provenance=row["provenance"] or "unknown",
            risk_assessment=assessment,
            risk_score=float(row["risk_score"] or 0),
            ranking_score=float(row["ranking_score"] or 0),
            risk_breakdown=json.loads(row["risk_breakdown"] or "[]"),
            finding_rule_ids=json.loads(row["finding_rule_ids"] or "[]"),
            assessment_reviewer=reviewer,
            assessment_reason=reason,
            assessment_reviewed_at=reviewed_at,
            ti_provider=row["ti_provider"] or "",
            ti_verdict=row["ti_verdict"] or "unknown",
            ti_confidence=float(row["ti_confidence"] or 0),
            registered=bool(row["registered"]), first_seen=row["first_seen"] or "",
            last_seen=row["last_seen"] or "",
        )

    def set_asset_ti(self, asset_id: str, *, provider: str,
                     verdict: str, confidence: float) -> AssetRecord | None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE assets SET ti_provider=?,ti_verdict=?,ti_confidence=? WHERE asset_id=?",
                (provider, verdict, confidence, asset_id),
            )
            row = conn.execute("SELECT * FROM assets WHERE asset_id=?", (asset_id,)).fetchone()
        if row is None:
            return None
        reviews = self._asset_review(asset_id)
        return AssetRecord(
            asset_id=row["asset_id"], kind=AssetKind(row["kind"]), name=row["name"],
            version=row["version"] or "", path=row["path"] or "", sha256=row["sha256"] or "",
            host=row["host"] or "", owner=row["owner"] or "", source=row["source"] or "",
            provenance=row["provenance"] or "unknown",
            risk_assessment=RiskAssessment(reviews["risk_assessment"] if reviews else
                                           row["risk_assessment"] or "unassessed"),
            risk_score=float(row["risk_score"] or 0),
            ranking_score=float(row["ranking_score"] or 0),
            risk_breakdown=json.loads(row["risk_breakdown"] or "[]"),
            finding_rule_ids=json.loads(row["finding_rule_ids"] or "[]"),
            assessment_reviewer=reviews["reviewer"] if reviews else "",
            assessment_reason=reviews["reason"] if reviews else "",
            assessment_reviewed_at=reviews["reviewed_at"] if reviews else "",
            ti_provider=provider, ti_verdict=verdict, ti_confidence=confidence,
            registered=bool(row["registered"]), first_seen=row["first_seen"] or "",
            last_seen=row["last_seen"] or "",
        )

    def get_asset(self, asset_id: str) -> AssetRecord | None:
        return next((asset for asset in self.list_assets()
                     if asset.asset_id == asset_id or asset.instance_id == asset_id
                     or asset.logical_id == asset_id), None)

    def mark_asset_used(self, asset_id: str, *, used_at: str | None = None) -> bool:
        timestamp = used_at or utc_now_iso()
        with self._connect() as conn:
            cursor = conn.execute(
                "UPDATE assets SET state='active',installation_state='installed',"
                "activation_state='enabled',runtime_state='active',"
                "last_used_at=?,last_seen=?"
                " WHERE asset_id=? AND state != 'removed'",
                (timestamp, timestamp, asset_id),
            )
        return cursor.rowcount > 0

    def record_admission_decision(self, *, decision_id: str, logical_id: str,
                                  release_id: str, instance_id: str,
                                  content_hash: str, requested_state: str,
                                  action: str, policy_version: str,
                                  checks: list[dict[str, Any]], reason: str,
                                  created_at: str, expires_at: str = "") -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO admission_decisions (decision_id,logical_id,release_id,instance_id,"
                "content_hash,requested_state,action,policy_version,checks_json,reason,created_at,expires_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (decision_id, logical_id, release_id, instance_id, content_hash,
                 requested_state, action, policy_version,
                 json.dumps(checks, ensure_ascii=False), reason, created_at, expires_at),
            )

    def record_runtime_enforcement(self, enforcement: dict[str, Any]) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO runtime_enforcements (enforcement_id,event_id,"
                "requested_action,actual_action,product_ack,exit_code,enforcement_result,"
                "adapter_version,ts) VALUES (?,?,?,?,?,?,?,?,?)",
                (enforcement["enforcement_id"], enforcement["event_id"],
                 enforcement["requested_action"], enforcement["actual_action"],
                 int(enforcement.get("product_ack", False)), enforcement.get("exit_code"),
                 enforcement.get("enforcement_result", "unknown"),
                 enforcement.get("adapter_version", ""), enforcement.get("ts", utc_now_iso())),
            )

    def _asset_review(self, asset_id: str) -> dict[str, str] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM asset_reviews WHERE asset_id=?", (asset_id,)).fetchone()
        return dict(row) if row else None

    def enroll_device(self, *, device_id: str, hostname: str, owner: str,
                      host_role: str, platform: str,
                      token_sha256: str) -> DeviceRecord:
        """Register a host and persist only the hash of its upload token."""
        now = utc_now_iso()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO devices (device_id, hostname, owner, host_role, platform, token_sha256,"
                " created_at, last_seen) VALUES (?,?,?,?,?,?,?,?)"
                " ON CONFLICT(device_id) DO UPDATE SET hostname=excluded.hostname, owner=excluded.owner,"
                " host_role=excluded.host_role, platform=excluded.platform,"
                " token_sha256=excluded.token_sha256, created_at=excluded.created_at,"
                " last_seen=NULL, token_revoked_at=NULL",
                (device_id, hostname, owner, host_role, platform, token_sha256, now, None),
            )
        return DeviceRecord(device_id=device_id, hostname=hostname, owner=owner,
                            host_role=host_role, platform=platform,
                            created_at=now, last_seen="")

    def authenticate_device(self, token_sha256: str) -> DeviceRecord | None:
        """Authenticate an enrolled endpoint token and update its heartbeat."""
        now = utc_now_iso()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT device_id, hostname, owner, host_role, platform, created_at, token_revoked_at"
                " FROM devices WHERE token_sha256 = ?", (token_sha256,)
            ).fetchone()
            if row is None or row["token_revoked_at"]:
                return None
            conn.execute(
                "UPDATE devices SET last_seen = ? WHERE device_id = ?",
                (now, row["device_id"]),
            )
        return DeviceRecord(
            device_id=row["device_id"], hostname=row["hostname"], owner=row["owner"] or "",
            host_role=row["host_role"] or "", platform=row["platform"] or "",
            created_at=row["created_at"] or "", last_seen=now,
        )

    def list_devices(self) -> list[DeviceRecord]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT device_id, hostname, owner, host_role, platform, created_at, last_seen, token_revoked_at"
                " FROM devices ORDER BY hostname, device_id"
            ).fetchall()
        return [DeviceRecord(
            device_id=row["device_id"], hostname=row["hostname"], owner=row["owner"] or "",
            host_role=row["host_role"] or "", platform=row["platform"] or "",
            created_at=row["created_at"] or "", last_seen=row["last_seen"] or "",
            revoked_at=row["token_revoked_at"] or "",
        ) for row in rows]

    def revoke_device(self, device_id: str) -> DeviceRecord | None:
        now = utc_now_iso()
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE devices SET token_revoked_at = ? WHERE device_id = ?"
                " AND token_revoked_at IS NULL", (now, device_id))
            if cur.rowcount == 0:
                row = conn.execute(
                    "SELECT device_id, hostname, owner, host_role, platform, created_at,"
                    " last_seen, token_revoked_at FROM devices WHERE device_id = ?",
                    (device_id,),
                ).fetchone()
            else:
                row = conn.execute(
                    "SELECT device_id, hostname, owner, host_role, platform, created_at,"
                    " last_seen, token_revoked_at FROM devices WHERE device_id = ?",
                    (device_id,),
                ).fetchone()
        if row is None:
            return None
        return DeviceRecord(
            device_id=row["device_id"], hostname=row["hostname"], owner=row["owner"] or "",
            host_role=row["host_role"] or "", platform=row["platform"] or "",
            created_at=row["created_at"] or "", last_seen=row["last_seen"] or "",
            revoked_at=row["token_revoked_at"] or "",
        )

    def touch_device(self, device_id: str) -> None:
        with self._connect() as conn:
            conn.execute("UPDATE devices SET last_seen = ? WHERE device_id = ?",
                         (utc_now_iso(), device_id))

    def device_health_rows(self) -> list[dict[str, Any]]:
        """Join endpoint registry with most recent uploaded heartbeat evidence."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT d.device_id,d.hostname,d.owner,d.host_role,d.platform,d.created_at,"
                " d.last_seen,d.token_revoked_at, e.ts AS heartbeat_ts,e.evidence AS heartbeat_evidence"
                " FROM devices d LEFT JOIN events e ON e.event_id = ("
                "   SELECT e2.event_id FROM events e2 WHERE e2.host=d.hostname"
                "   AND e2.event_type='heartbeat' ORDER BY e2.ts DESC LIMIT 1)"
                " ORDER BY d.hostname,d.device_id"
            ).fetchall()
        result = []
        now = datetime.now(timezone.utc)
        for row in rows:
            try:
                evidence = json.loads(row["heartbeat_evidence"] or "{}")
            except json.JSONDecodeError:
                evidence = {}
            hb_age = None
            if row["heartbeat_ts"]:
                try:
                    heartbeat_time = datetime.fromisoformat(row["heartbeat_ts"].replace("Z", "+00:00"))
                    hb_age = max(0, int((now - heartbeat_time).total_seconds()))
                except ValueError:
                    pass
            revoked = bool(row["token_revoked_at"])
            if revoked:
                state = "revoked"
            elif hb_age is None:
                state = "never_seen"
            elif hb_age <= 120 and not int(evidence.get("upload_fail_count", 0) or 0):
                state = "online"
            elif hb_age <= 300:
                state = "degraded"
            else:
                state = "offline"
            result.append({
                "device_id": row["device_id"], "hostname": row["hostname"],
                "owner": row["owner"] or "", "host_role": row["host_role"] or "",
                "platform": row["platform"] or "", "created_at": row["created_at"],
                "last_upload_at": row["last_seen"] or "",
                "heartbeat_at": row["heartbeat_ts"] or "",
                "heartbeat_age_seconds": hb_age,
                "state": state,
                "pending_events": int(evidence.get("pending_events", 0) or 0),
                "oldest_pending_age_seconds": evidence.get("oldest_pending_age_seconds"),
                "upload_fail_count": int(evidence.get("upload_fail_count", 0) or 0),
                "audit_offset": int(evidence.get("audit_offset", 0) or 0),
                "audit_lost": int(evidence.get("audit_lost", 0) or 0),
            })
        return result

    # ---------- scans ----------

    def record_scan(self, report: ScanReport) -> None:
        carrier = (report.carrier if report.carrier != AssetCarrier.UNKNOWN
                   else classify_carrier(report.target_path))
        state = (report.state if report.state != AssetState.DISCOVERED
                 else state_for_carrier(carrier))
        score = score_findings(report.findings, state=state.value)
        assessment = RiskAssessment(score["assessment"])
        assessment_reason = str(score["reason"])
        inventory_only = report.inventory_only or state not in {
            AssetState.INSTALLED, AssetState.ENABLED, AssetState.ACTIVE,
        } or carrier == AssetCarrier.SYNTHETIC
        product = report.product or infer_product(report.target_path)
        logical_id, instance_id = derive_ids(
            product=product, kind=report.target_kind, name=report.target_name,
            host=report.host, carrier=carrier, path=report.target_path,
        )
        logical_id = report.logical_id or logical_id
        instance_id = report.instance_id or instance_id
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO scans (scan_id, ts, host, target_kind, target_name,"
                " target_path, sha256, verdict, findings, risk_assessment,risk_score,ranking_score,risk_breakdown,"
                " assessment_reason,"
                " ti_provider, ti_verdict, ti_confidence,product,logical_id,instance_id,"
                "content_hash,carrier,state,scope,inventory_only,ti_iocs,execution_origin)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (report.scan_id, report.ts, report.host, report.target_kind.value,
                 report.target_name, report.target_path, report.sha256,
                 report.verdict.value,
                 json.dumps([f.model_dump() for f in report.findings], ensure_ascii=False),
                 assessment.value, score["score"], score["ranking_score"],
                 json.dumps(score["breakdown"], ensure_ascii=False),
                 assessment_reason, report.ti_provider,
                 report.ti_verdict, report.ti_confidence, product, logical_id,
                 instance_id, report.content_hash or report.sha256, carrier.value,
                 state.value, report.scope, int(inventory_only),
                 json.dumps(report.ti_iocs, ensure_ascii=False),
                 json.dumps(report.execution_origin, ensure_ascii=False)),
            )
            matches = conn.execute(
                "SELECT asset_id, registered, owner, source, provenance,"
                "risk_assessment,finding_rule_ids,ti_provider,ti_verdict,ti_confidence"
                " FROM assets WHERE instance_id = ? OR"
                " (kind = ? AND name = ? AND path = ? AND host = ?)"
                " ORDER BY registered DESC, CASE source WHEN 'managed-inventory' THEN 0"
                " WHEN 'agentsec-inventory' THEN 1 ELSE 2 END, first_seen LIMIT 1",
                (instance_id, report.target_kind.value, report.target_name,
                 report.target_path, report.host),
            ).fetchall()
            asset_id = matches[0]["asset_id"] if matches else instance_id
            owner = matches[0]["owner"] if matches else ""
            source = matches[0]["source"] if matches else ""
            registered = report.registered or any(bool(row["registered"]) for row in matches)
            provenance = matches[0]["provenance"] if matches else legacy_provenance(carrier)
            prior_assessment = matches[0]["risk_assessment"] if matches else "unassessed"
            prior_rules = json.loads(matches[0]["finding_rule_ids"] or "[]") if matches else []
            ti_provider = matches[0]["ti_provider"] if matches else ""
            ti_verdict = matches[0]["ti_verdict"] if matches else "unknown"
            ti_confidence = float(matches[0]["ti_confidence"] or 0) if matches else 0.0
        new_asset = AssetRecord(
            asset_id=asset_id,
            kind=report.target_kind,
            name=report.target_name,
            path=report.target_path,
            sha256=report.sha256,
            host=report.host,
            owner=owner or "",
            source=source or "",
            registered=registered,
            provenance=provenance or legacy_provenance(carrier),
            risk_assessment=(assessment if report.findings else
                             RiskAssessment(prior_assessment or "unassessed")),
            risk_score=score["score"],
            ranking_score=score["ranking_score"],
            risk_breakdown=score["breakdown"],
            finding_rule_ids=sorted(set(prior_rules) |
                                    {finding.rule_id for finding in report.findings}),
            ti_provider=ti_provider,
            ti_verdict=ti_verdict,
            ti_confidence=ti_confidence,
            product=product,
            logical_id=logical_id,
            instance_id=instance_id,
            content_hash=report.content_hash or report.sha256,
            carrier=carrier,
            state=state,
            scope=report.scope,
        )
        self.upsert_asset(new_asset)
        if inventory_only:
            return
        self.insert_event(
            SecurityEvent(
                event_id=f"evt-scan-{report.scan_id}",
                ts=report.ts,
                source=EventSource.SCANNER,
                event_type=EventType.SCAN_FINDING,
                host=report.host,
                target_kind=report.target_kind.value,
                target_path=report.target_path,
                action=SecurityAction.ALERT if report.verdict.value != "clean" else SecurityAction.AUDIT,
                rule_ids=[f.rule_id for f in report.findings],
                severity=self._max_severity(report),
                evidence={"scan_id": report.scan_id, "verdict": report.verdict.value,
                          "target_name": report.target_name},
            )
        )

    @staticmethod
    def _max_severity(report: ScanReport) -> Severity:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        if not report.findings:
            return Severity.INFO
        return max((f.severity for f in report.findings), key=order.index)

    def list_scans(self, *, host: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        clauses = ""
        params: list[Any] = []
        if host:
            clauses = " WHERE host = ?"
            params.append(host)
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT scan_id, ts, host, target_kind, target_name, target_path, sha256, verdict,"
                " findings, risk_assessment, risk_score,ranking_score,risk_breakdown,assessment_reason,"
                " ti_provider, ti_verdict, ti_confidence,"
                " product,logical_id,instance_id,content_hash,carrier,state,scope,inventory_only,ti_iocs,execution_origin"
                f" FROM scans{clauses} ORDER BY ts DESC LIMIT ?", params
            ).fetchall()
        return [{
            **dict(row),
            "findings": json.loads(row["findings"] or "[]"),
            "risk_breakdown": json.loads(row["risk_breakdown"] or "[]"),
            "ti_iocs": json.loads(row["ti_iocs"] or "[]"),
            "execution_origin": json.loads(row["execution_origin"] or "{}"),
        } for row in rows]

    # ---------- policies ----------

    def upsert_policy(self, policy: PolicyRule) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO policies (policy_id, name, kind, pattern, severity, action,"
                " enabled, updated_at, note) VALUES (?,?,?,?,?,?,?,?,?)",
                (policy.policy_id, policy.name, policy.kind, policy.pattern, policy.severity.value,
                 policy.action.value, int(policy.enabled),
                 policy.updated_at or utc_now_iso(), policy.note),
            )

    def list_policies(self, *, kind: str | None = None) -> list[PolicyRule]:
        clauses = ""
        params: list[Any] = []
        if kind:
            clauses = " WHERE kind = ?"
            params.append(kind)
        with self._connect() as conn:
            rows = conn.execute(f"SELECT * FROM policies{clauses} ORDER BY policy_id", params).fetchall()
        return [
            PolicyRule(
                policy_id=row["policy_id"],
                name=row["name"],
                kind=row["kind"],
                pattern=row["pattern"],
                severity=Severity(row["severity"]),
                action=SecurityAction(row["action"]),
                enabled=bool(row["enabled"]),
                updated_at=row["updated_at"] or "",
                note=row["note"] or "",
            )
            for row in rows
        ]

    # ---------- ioc cache ----------

    def get_cached_ioc(self, ioc: str, *, now: str | None = None) -> dict[str, Any] | None:
        now = now or utc_now_iso()
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM ioc_cache WHERE ioc = ?", (ioc,)).fetchone()
        if row is None:
            return None
        item = dict(row)
        if item["expires_at"] and item["expires_at"] < now:
            return None
        return item

    def put_cached_ioc(
        self,
        ioc: str,
        ioc_type: str,
        verdict: str,
        confidence: float,
        *,
        ttl_days: int = 7,
        provider: str = "threatbook",
    ) -> None:
        from datetime import datetime, timedelta, timezone

        now = datetime.now(timezone.utc)
        expires = now + timedelta(days=ttl_days)
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO ioc_cache (ioc, ioc_type, verdict, confidence, provider,"
                " fetched_at, expires_at) VALUES (?,?,?,?,?,?,?)",
                (ioc, ioc_type, verdict, confidence, provider,
                 now.isoformat(), expires.isoformat()),
            )

    def record_ioc_query(self, *, ioc: str, ioc_type: str, provider: str,
                         verdict: str, confidence: float, cached: bool,
                         reason: str, queried_at: str | None = None) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO ioc_queries (ioc,ioc_type,provider,queried_at,verdict,"
                "confidence,cached,reason) VALUES (?,?,?,?,?,?,?,?)",
                (ioc, ioc_type, provider, queried_at or utc_now_iso(), verdict,
                 confidence, int(cached), reason[:300]),
            )

    def list_ioc_queries(self, *, ioc_type: str | None = None,
                         limit: int = 100) -> list[dict[str, Any]]:
        where = " WHERE ioc_type = ?" if ioc_type else ""
        params: list[Any] = [ioc_type] if ioc_type else []
        params.append(max(1, min(limit, 500)))
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT query_id,ioc,ioc_type,provider,queried_at,verdict,confidence,cached,reason"
                f" FROM ioc_queries{where} ORDER BY queried_at DESC,query_id DESC LIMIT ?",
                params,
            ).fetchall()
        return [{**dict(row), "cached": bool(row["cached"])} for row in rows]

    # ---------- stats ----------

    def stats(self) -> dict[str, Any]:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) AS c FROM events").fetchone()["c"]
            by_severity = {
                row["severity"]: row["c"]
                for row in conn.execute(
                    "SELECT severity, COUNT(*) AS c FROM events GROUP BY severity"
                ).fetchall()
            }
            by_action = {
                row["action"]: row["c"]
                for row in conn.execute(
                    "SELECT action, COUNT(*) AS c FROM events GROUP BY action"
                ).fetchall()
            }
            by_source = {
                row["source"]: row["c"]
                for row in conn.execute(
                    "SELECT source, COUNT(*) AS c FROM events GROUP BY source"
                ).fetchall()
            }
            by_rule: dict[str, int] = {}
            for row in conn.execute("SELECT rule_ids FROM events WHERE rule_ids != '[]'").fetchall():
                for rule_id in json.loads(row["rule_ids"]):
                    by_rule[rule_id] = by_rule.get(rule_id, 0) + 1
            sessions = conn.execute("SELECT COUNT(*) AS c FROM sessions").fetchone()["c"]
            assets = conn.execute(
                "SELECT COUNT(DISTINCT logical_id) AS c FROM assets"
                " WHERE state IN ('installed','enabled','active') AND carrier != 'synthetic'"
            ).fetchone()["c"]
            asset_instances = conn.execute("SELECT COUNT(*) AS c FROM assets").fetchone()["c"]
            inventory_instances = conn.execute(
                "SELECT COUNT(*) AS c FROM assets WHERE state IN ('discovered','cached')"
                " OR carrier='synthetic' OR carrier='vendor_dependency'"
            ).fetchone()["c"]
            scans = conn.execute("SELECT COUNT(*) AS c FROM scans").fetchone()["c"]
            asset_provenance = {row["provenance"]: row["c"] for row in conn.execute(
                "SELECT provenance,COUNT(*) AS c FROM assets GROUP BY provenance").fetchall()}
            asset_risk = {row["risk_assessment"]: row["c"] for row in conn.execute(
                "SELECT risk_assessment,COUNT(*) AS c FROM assets"
                " WHERE state IN ('installed','enabled','active') AND carrier != 'synthetic'"
                " GROUP BY risk_assessment").fetchall()}
            inventory_asset_risk = {row["risk_assessment"]: row["c"] for row in conn.execute(
                "SELECT risk_assessment,COUNT(*) AS c FROM assets"
                " WHERE state NOT IN ('installed','enabled','active') OR carrier='synthetic'"
                " GROUP BY risk_assessment").fetchall()}
            scan_verdicts = {row["verdict"]: row["c"] for row in conn.execute(
                "SELECT verdict,COUNT(*) AS c FROM scans WHERE inventory_only=0 GROUP BY verdict").fetchall()}
            inventory_scan_verdicts = {row["verdict"]: row["c"] for row in conn.execute(
                "SELECT verdict,COUNT(*) AS c FROM scans WHERE inventory_only=1 GROUP BY verdict").fetchall()}
            scan_assessments = {row["risk_assessment"]: row["c"] for row in conn.execute(
                "SELECT risk_assessment,COUNT(*) AS c FROM scans WHERE inventory_only=0"
                " GROUP BY risk_assessment").fetchall()}
            inventory_scan_assessments = {row["risk_assessment"]: row["c"] for row in conn.execute(
                "SELECT risk_assessment,COUNT(*) AS c FROM scans WHERE inventory_only=1"
                " GROUP BY risk_assessment").fetchall()}
            ti_events = {row["ti_verdict"]: row["c"] for row in conn.execute(
                "SELECT ti_verdict,COUNT(*) AS c FROM events WHERE ti_provider != '' GROUP BY ti_verdict").fetchall()}
        return {
            "events_total": total,
            "by_severity": by_severity,
            "by_action": by_action,
            "by_source": by_source,
            "by_rule": dict(sorted(by_rule.items(), key=lambda kv: -kv[1])),
            "sessions": sessions,
            "assets": assets,
            "asset_instances": asset_instances,
            "inventory_asset_instances": inventory_instances,
            "scans": scans,
            "asset_provenance": asset_provenance,
            "asset_risk_assessment": asset_risk,
            "inventory_asset_risk_assessment": inventory_asset_risk,
            "scan_policy_verdicts": scan_verdicts,
            "inventory_scan_verdicts": inventory_scan_verdicts,
            "scan_risk_assessment": scan_assessments,
            "inventory_scan_risk_assessment": inventory_scan_assessments,
            "ti_event_verdicts": ti_events,
        }
