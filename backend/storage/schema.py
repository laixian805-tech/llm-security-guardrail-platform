"""ASGP 存储 schema 与迁移。

当前用 SQLite 开发；多设备正式环境迁 PostgreSQL。表结构按 DATA_MODEL.md
的领域实体拆，不再复用旧原型把资产、事件、扫描塞在一张表的做法。

去重约束落在数据库层：findings 对 (detector_id, fingerprint) 唯一，
重扫同一目标不会积累重复 Finding；detector_runs 的 idempotency_key
唯一，调用方重试不会重复登记同一次执行。
"""

from __future__ import annotations

import sqlite3

SCHEMA_VERSION = 4

DDL = """
CREATE TABLE IF NOT EXISTS detector_runs (
    detector_run_id TEXT PRIMARY KEY,
    idempotency_key TEXT UNIQUE,
    detector_id TEXT NOT NULL,
    detector_version TEXT NOT NULL,
    asset_id TEXT,
    instance_id TEXT,
    target_ref TEXT NOT NULL,
    mode TEXT NOT NULL,
    status TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    timeout_seconds INTEGER NOT NULL,
    error TEXT,
    normalizer_version TEXT NOT NULL,
    finding_count INTEGER NOT NULL DEFAULT 0,
    provider_profile_id TEXT,
    model_id TEXT,
    wire_api TEXT,
    latency_ms INTEGER,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS raw_reports (
    raw_report_id TEXT PRIMARY KEY,
    detector_run_id TEXT NOT NULL REFERENCES detector_runs(detector_run_id) ON DELETE CASCADE,
    uri TEXT NOT NULL,
    media_type TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    byte_length INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    -- 首次观察到该 Finding 的 run。Finding 按指纹去重、可被后续 run 复用，
    -- 所以这个引用不能级联删除：originating run 过期时只置空，不牵连仍在
    -- 保留期内的其它 run。无 originating run 时记 NULL。
    detector_run_id TEXT REFERENCES detector_runs(detector_run_id),
    asset_id TEXT,
    instance_id TEXT,
    execution_id TEXT,
    detector_id TEXT NOT NULL,
    detector_version TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    upstream_rule_id TEXT,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    title TEXT NOT NULL,
    message TEXT NOT NULL DEFAULT '',
    fingerprint TEXT NOT NULL,
    status TEXT NOT NULL,
    upstream_risk_score REAL,
    evidence_refs TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (detector_id, fingerprint)
);

-- 一次 run 观察到哪些 Finding；Finding 本身按指纹去重，不随重试复制。
CREATE TABLE IF NOT EXISTS detector_run_findings (
    detector_run_id TEXT NOT NULL REFERENCES detector_runs(detector_run_id) ON DELETE CASCADE,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
    PRIMARY KEY (detector_run_id, finding_id)
);

CREATE TABLE IF NOT EXISTS schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS provider_probes (
    probe_id TEXT PRIMARY KEY,
    provider_id TEXT NOT NULL,
    profile_kind TEXT NOT NULL,
    wire_api TEXT NOT NULL,
    base_url TEXT NOT NULL,
    model TEXT NOT NULL,
    status TEXT NOT NULL,
    latency_ms INTEGER,
    http_status INTEGER,
    error_kind TEXT,
    error TEXT,
    capabilities TEXT NOT NULL DEFAULT '[]',
    probed_at TEXT NOT NULL,
    UNIQUE (provider_id, profile_kind)
);

-- 控制台用户与设备身份分开存放：设备令牌只代表端点上报资格，不带控制台权限。
CREATE TABLE IF NOT EXISTS console_users (
    user_id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TEXT NOT NULL,
    disabled_at TEXT
);

CREATE TABLE IF NOT EXISTS console_sessions (
    session_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES console_users(user_id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);
CREATE INDEX IF NOT EXISTS console_sessions_user ON console_sessions(user_id);

CREATE TABLE IF NOT EXISTS device_identities (
    device_id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    credential_hash TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    enrolled_at TEXT NOT NULL,
    last_seen_at TEXT
);

CREATE TABLE IF NOT EXISTS audit_events (
    audit_id TEXT PRIMARY KEY,
    occurred_at TEXT NOT NULL,
    request_id TEXT NOT NULL,
    actor_kind TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL DEFAULT '',
    outcome TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS audit_events_time ON audit_events(occurred_at);
CREATE INDEX IF NOT EXISTS audit_events_actor ON audit_events(actor_kind, actor_id);

CREATE TABLE IF NOT EXISTS retention_rules (
    data_kind TEXT PRIMARY KEY,
    retention_days INTEGER NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL
);
"""

INDEX_DDL = """
CREATE INDEX IF NOT EXISTS detector_runs_detector ON detector_runs(detector_id, started_at);
CREATE INDEX IF NOT EXISTS detector_runs_target ON detector_runs(target_ref);
CREATE INDEX IF NOT EXISTS raw_reports_run ON raw_reports(detector_run_id);
CREATE INDEX IF NOT EXISTS findings_run ON findings(detector_run_id);
CREATE INDEX IF NOT EXISTS findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS findings_status ON findings(status);
"""


def table_names(conn: sqlite3.Connection) -> set[str]:
    rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    return {row[0] for row in rows}


def _migrate_v1(conn: sqlite3.Connection) -> None:
    """把旧原型的 scans/findings 两表迁入 DetectorRun/RawReport/Finding。

    旧表没有 detector_version 和 normalizer_version，统一记为 unknown 与
    legacy 归一化器版本；指纹为空的 Finding 用引擎、规则、位置和消息重新
    计算，保证迁移后仍受唯一约束保护。
    """
    from adapters.detectors.normalize import make_fingerprint

    scans = conn.execute(
        "SELECT scan_id, engine, target, status, started_at, finished_at, raw_report"
        " FROM scans_legacy"
    ).fetchall()
    started_at_by_run = {row["scan_id"]: row["started_at"] for row in scans}

    for row in scans:
        scan_id = row["scan_id"]
        run_status = "succeeded" if row["status"] in ("completed", "imported") else row["status"]
        conn.execute(
            "INSERT OR REPLACE INTO detector_runs (detector_run_id, detector_id, detector_version,"
            " target_ref, mode, status, started_at, finished_at, timeout_seconds, error,"
            " normalizer_version, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (scan_id, row["engine"], "unknown", row["target"], "static", run_status,
             row["started_at"], row["finished_at"], 300,
             None if run_status == "succeeded" else "legacy scan failed",
             "legacy-1.0.0", row["finished_at"] or row["started_at"]),
        )
        if row["raw_report"]:
            conn.execute(
                "INSERT OR REPLACE INTO raw_reports (raw_report_id, detector_run_id, uri, media_type,"
                " sha256, byte_length, content, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (f"raw_{scan_id}", scan_id, f"legacy/scans/{scan_id}", "application/json",
                 "0" * 64, len(row["raw_report"].encode("utf-8")), row["raw_report"],
                 row["finished_at"] or row["started_at"]),
            )

    legacy_findings = conn.execute(
        "SELECT finding_id, scan_id, engine, rule_id, title, severity, message, file, line,"
        " risk_score, fingerprint FROM findings_legacy"
    ).fetchall()
    for row in legacy_findings:
        location = f"{row['file']}:{row['line']}" if row["line"] else row["file"]
        fingerprint = row["fingerprint"] or make_fingerprint(
            row["engine"], row["rule_id"], location, row["message"]
        )
        created_at = started_at_by_run.get(row["scan_id"], "1970-01-01T00:00:00+00:00")
        conn.execute(
            "INSERT OR IGNORE INTO findings (finding_id, detector_run_id, detector_id,"
            " detector_version, rule_id, upstream_rule_id, severity, confidence, title, message,"
            " fingerprint, status, upstream_risk_score, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (row["finding_id"], row["scan_id"], row["engine"], "unknown", row["rule_id"],
             row["rule_id"], row["severity"] or "unknown", "unknown", row["title"],
             row["message"], fingerprint, "new", row["risk_score"], created_at, created_at),
        )
        conn.execute(
            "INSERT OR IGNORE INTO detector_run_findings (detector_run_id, finding_id) VALUES (?,?)",
            (row["scan_id"], row["finding_id"]),
        )

    conn.execute(
        "UPDATE detector_runs SET finding_count = (SELECT COUNT(*) FROM detector_run_findings"
        " WHERE detector_run_findings.detector_run_id = detector_runs.detector_run_id)"
    )


def _rebuild_findings_without_cascade(conn: sqlite3.Connection) -> None:
    """去掉 findings.detector_run_id 的 ON DELETE CASCADE。

    Finding 按指纹去重、可被多次 run 复用，originating run 过期级联删除它
    会牵连仍在保留期内的其它 run。重建时保留全部 finding_id，链接表不动。
    """
    conn.execute("PRAGMA foreign_keys=OFF")
    try:
        conn.execute(
            "CREATE TABLE findings_rebuild ("
            " finding_id TEXT PRIMARY KEY,"
            " detector_run_id TEXT REFERENCES detector_runs(detector_run_id),"
            " asset_id TEXT, instance_id TEXT, execution_id TEXT,"
            " detector_id TEXT NOT NULL, detector_version TEXT NOT NULL,"
            " rule_id TEXT NOT NULL, upstream_rule_id TEXT, severity TEXT NOT NULL,"
            " confidence TEXT NOT NULL, title TEXT NOT NULL, message TEXT NOT NULL DEFAULT '',"
            " fingerprint TEXT NOT NULL, status TEXT NOT NULL, upstream_risk_score REAL,"
            " evidence_refs TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL,"
            " updated_at TEXT NOT NULL, UNIQUE (detector_id, fingerprint))"
        )
        conn.execute(
            "INSERT INTO findings_rebuild (finding_id, detector_run_id, asset_id, instance_id,"
            " execution_id, detector_id, detector_version, rule_id, upstream_rule_id, severity,"
            " confidence, title, message, fingerprint, status, upstream_risk_score,"
            " evidence_refs, created_at, updated_at)"
            " SELECT finding_id, detector_run_id, asset_id, instance_id, execution_id,"
            " detector_id, detector_version, rule_id, upstream_rule_id, severity, confidence,"
            " title, message, fingerprint, status, upstream_risk_score, evidence_refs,"
            " created_at, updated_at FROM findings"
        )
        conn.execute("DROP TABLE findings")
        conn.execute("ALTER TABLE findings_rebuild RENAME TO findings")
        conn.executescript(INDEX_DDL)
    finally:
        conn.execute("PRAGMA foreign_keys=ON")


def migrate(conn: sqlite3.Connection) -> None:
    """建表并按需迁移；重复执行安全。"""
    tables = table_names(conn)
    has_v1 = "scans" in tables and "findings" in tables
    has_v2 = "detector_runs" in tables
    has_v4 = "console_users" in tables

    if has_v1 and not has_v2:
        # 旧 findings 与新 findings 同名，必须先让位，否则 CREATE IF NOT EXISTS
        # 会把旧表当成新表跳过，后面的新列引用全部失败。
        conn.execute("ALTER TABLE scans RENAME TO scans_legacy")
        conn.execute("ALTER TABLE findings RENAME TO findings_legacy")

    conn.executescript(DDL)

    if has_v1 and not has_v2:
        _migrate_v1(conn)

    if has_v2 and not has_v4:
        # v2/v3 的 findings 带级联删除，保留策略会误删仍在用的 Finding。
        _rebuild_findings_without_cascade(conn)

    conn.executescript(INDEX_DDL)
    conn.execute(
        "INSERT INTO schema_meta (key, value) VALUES ('schema_version', ?)"
        " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (str(SCHEMA_VERSION),),
    )


def connect(path) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn
