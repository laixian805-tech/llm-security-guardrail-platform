"""ASGP 存储 schema 与迁移。

当前用 SQLite 开发；多设备正式环境迁 PostgreSQL。表结构按 DATA_MODEL.md
的领域实体拆，不再复用旧原型把资产、事件、扫描塞在一张表的做法。

去重约束落在数据库层：findings 对 (detector_id, fingerprint) 唯一，
重扫同一目标不会积累重复 Finding；detector_runs 的 idempotency_key
唯一，调用方重试不会重复登记同一次执行。
"""

from __future__ import annotations

import sqlite3

SCHEMA_VERSION = 6

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

-- host_id 是服务端覆盖客户端 host 身份的权威来源（P1）：摄入时请求体里
-- 的 host_id 被忽略，一律以设备行的绑定值为准。credential_rotated_at
-- 记录令牌轮换时间；轮换是硬切换，旧令牌立即失效。
CREATE TABLE IF NOT EXISTS device_identities (
    device_id TEXT PRIMARY KEY,
    label TEXT NOT NULL,
    credential_hash TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    enrolled_at TEXT NOT NULL,
    last_seen_at TEXT,
    host_id TEXT,
    credential_rotated_at TEXT
);

-- 一次 Agent 任务/会话的执行边界。UNIQUE(host_id, product, session_id)
-- 保证同一会话只有一条 Execution：端点重装或重放都不会分裂出第二条。
CREATE TABLE IF NOT EXISTS executions (
    execution_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    device_id TEXT NOT NULL REFERENCES device_identities(device_id),
    product TEXT NOT NULL,
    product_version TEXT NOT NULL,
    session_id TEXT NOT NULL,
    -- P1 无资产注册表：只存端点上报的引用，不做存在性校验。
    asset_instance_id TEXT,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    outcome TEXT NOT NULL,
    intent_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (host_id, product, session_id)
);

-- 观测到的工具调用。同一 (execution_id, tool_call_id) 只保留一条：
-- PreToolUse 创建并可能带决策，PostToolUse 只补结果。tool_call_id 为
-- NULL 时唯一约束不触发（SQLite 语义），产品不提供调用 ID 时每次观测
-- 各自成条，按 intent_id 幂等。
CREATE TABLE IF NOT EXISTS intents (
    intent_id TEXT PRIMARY KEY,
    execution_id TEXT NOT NULL REFERENCES executions(execution_id) ON DELETE CASCADE,
    parent_intent_id TEXT REFERENCES intents(intent_id),
    tool_call_id TEXT,
    tool_name TEXT NOT NULL,
    hook_event_type TEXT NOT NULL,
    decision TEXT NOT NULL,
    decision_reason TEXT,
    -- 端侧脱敏后的参数摘要；tool_input 原文、prompt 正文不进库。
    params_summary TEXT NOT NULL DEFAULT '',
    params_sha256 TEXT,
    redaction_applied INTEGER NOT NULL DEFAULT 0,
    occurred_at TEXT NOT NULL,
    ended_at TEXT,
    product_result TEXT,
    created_at TEXT NOT NULL,
    UNIQUE (execution_id, tool_call_id)
);

-- 采集器观测到的运行时事件。intent_ref 只是采集器提示，不是外键：权威
-- 关联是 P2 的 EventAttribution。复合主键落实服务端幂等规则。
CREATE TABLE IF NOT EXISTS runtime_events (
    event_id TEXT NOT NULL,
    host_id TEXT NOT NULL,
    collector_id TEXT NOT NULL,
    device_id TEXT NOT NULL REFERENCES device_identities(device_id),
    execution_id TEXT REFERENCES executions(execution_id) ON DELETE CASCADE,
    intent_ref TEXT,
    event_type TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    received_at TEXT NOT NULL,
    pid INTEGER,
    ppid INTEGER,
    executable TEXT,
    resource_host TEXT,
    resource_port INTEGER,
    resource_path TEXT,
    action TEXT,
    result TEXT,
    sequence INTEGER,
    evidence_refs TEXT NOT NULL DEFAULT '[]',
    PRIMARY KEY (host_id, collector_id, event_id)
);

CREATE TABLE IF NOT EXISTS event_attributions (
    attribution_id TEXT PRIMARY KEY,
    intent_id TEXT NOT NULL REFERENCES intents(intent_id) ON DELETE CASCADE,
    event_id TEXT NOT NULL,
    host_id TEXT NOT NULL,
    collector_id TEXT NOT NULL,
    method TEXT NOT NULL,
    confidence TEXT NOT NULL,
    score REAL NOT NULL,
    selected INTEGER NOT NULL DEFAULT 0,
    evidence_refs TEXT NOT NULL DEFAULT '[]',
    rule_version TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (intent_id, host_id, collector_id, event_id, method),
    FOREIGN KEY (host_id,collector_id,event_id) REFERENCES runtime_events(host_id,collector_id,event_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS risk_assessments (
    assessment_id TEXT PRIMARY KEY,
    asset_id TEXT,
    execution_id TEXT,
    intrinsic_risk REAL NOT NULL,
    runtime_risk REAL NOT NULL,
    exposure_risk REAL NOT NULL,
    confidence TEXT NOT NULL,
    reasons TEXT NOT NULL DEFAULT '[]',
    evidence_refs TEXT NOT NULL DEFAULT '[]',
    rule_version TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS policy_decisions (
    decision_id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    policy_version TEXT NOT NULL,
    subject_kind TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    reason TEXT NOT NULL,
    evidence_refs TEXT NOT NULL DEFAULT '[]',
    enforcement_expected INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    expires_at TEXT
);

CREATE TABLE IF NOT EXISTS admissions (
    admission_id TEXT PRIMARY KEY,
    asset_instance_id TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    state TEXT NOT NULL,
    approved_by TEXT,
    observed_content_hash TEXT,
    failure_reason TEXT,
    transaction_id TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL DEFAULT '',
    owner TEXT,
    opened_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    closed_at TEXT
);

CREATE TABLE IF NOT EXISTS incident_evidence (
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    evidence_kind TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    added_at TEXT NOT NULL,
    PRIMARY KEY (incident_id, evidence_kind, evidence_id)
);

CREATE TABLE IF NOT EXISTS governance_transitions (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_kind TEXT NOT NULL, entity_id TEXT NOT NULL,
    from_state TEXT NOT NULL, to_state TEXT NOT NULL,
    actor_id TEXT NOT NULL, action TEXT NOT NULL, occurred_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS approval_requests (
    approval_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES device_identities(device_id),
    host_id TEXT NOT NULL,
    product TEXT NOT NULL, product_version TEXT NOT NULL,
    session_id TEXT NOT NULL, tool_call_id TEXT NOT NULL,
    tool_name TEXT NOT NULL, params_sha256 TEXT NOT NULL,
    state TEXT NOT NULL, requested_at TEXT NOT NULL, expires_at TEXT NOT NULL,
    resolved_at TEXT, resolved_by TEXT,
    UNIQUE (device_id,product,session_id,tool_call_id,params_sha256)
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
CREATE INDEX IF NOT EXISTS executions_host_time ON executions(host_id, started_at);
CREATE INDEX IF NOT EXISTS executions_session ON executions(session_id);
CREATE INDEX IF NOT EXISTS intents_execution_time ON intents(execution_id, occurred_at);
CREATE INDEX IF NOT EXISTS intents_tool_call ON intents(tool_call_id);
CREATE INDEX IF NOT EXISTS runtime_events_time ON runtime_events(host_id, occurred_at);
CREATE INDEX IF NOT EXISTS runtime_events_execution ON runtime_events(execution_id, occurred_at);
CREATE INDEX IF NOT EXISTS runtime_events_intent ON runtime_events(intent_ref);
CREATE INDEX IF NOT EXISTS attributions_event ON event_attributions(host_id, collector_id, event_id);
CREATE INDEX IF NOT EXISTS attributions_intent ON event_attributions(intent_id);
CREATE INDEX IF NOT EXISTS risk_assessments_subject ON risk_assessments(asset_id, execution_id);
CREATE INDEX IF NOT EXISTS policy_decisions_subject ON policy_decisions(subject_kind, subject_id, created_at);
CREATE INDEX IF NOT EXISTS admissions_asset ON admissions(asset_instance_id, updated_at);
CREATE INDEX IF NOT EXISTS incidents_status ON incidents(status, updated_at);
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


def _migrate_v5(conn: sqlite3.Connection) -> None:
    """v4 → v5：补设备的主机绑定与令牌轮换列。

    服务端要以设备注册记录覆盖客户端提交的 host 身份（API_CONTRACT §6），
    设备行必须先有权威 host_id。SQLite 的 ALTER TABLE ADD COLUMN 不可重复
    执行，先查 PRAGMA table_info 决定是否加列，保证 migrate() 幂等。
    """
    columns = {row[1] for row in conn.execute("PRAGMA table_info(device_identities)")}
    if "host_id" not in columns:
        conn.execute("ALTER TABLE device_identities ADD COLUMN host_id TEXT")
    if "credential_rotated_at" not in columns:
        conn.execute("ALTER TABLE device_identities ADD COLUMN credential_rotated_at TEXT")


def _ensure_attribution_foreign_keys(conn: sqlite3.Connection) -> None:
    """升级早期 v6 试运行表，让保留策略删除源证据时同时删除归因边。"""
    if conn.execute('PRAGMA foreign_key_list(event_attributions)').fetchall():
        return
    conn.commit()
    try:
        conn.executescript('''BEGIN;
            CREATE TABLE event_attributions_rebuild (
              attribution_id TEXT PRIMARY KEY,
              intent_id TEXT NOT NULL REFERENCES intents(intent_id) ON DELETE CASCADE,
              event_id TEXT NOT NULL, host_id TEXT NOT NULL, collector_id TEXT NOT NULL,
              method TEXT NOT NULL, confidence TEXT NOT NULL, score REAL NOT NULL,
              selected INTEGER NOT NULL DEFAULT 0, evidence_refs TEXT NOT NULL DEFAULT '[]',
              rule_version TEXT NOT NULL, created_at TEXT NOT NULL,
              UNIQUE(intent_id,host_id,collector_id,event_id,method),
              FOREIGN KEY(host_id,collector_id,event_id)
                REFERENCES runtime_events(host_id,collector_id,event_id) ON DELETE CASCADE);
            INSERT INTO event_attributions_rebuild SELECT * FROM event_attributions;
            DROP TABLE event_attributions;
            ALTER TABLE event_attributions_rebuild RENAME TO event_attributions;
            COMMIT;''')
    except Exception:
        conn.rollback()
        raise


def migrate(conn: sqlite3.Connection) -> None:
    """建表并按需迁移；重复执行安全。"""
    tables = table_names(conn)
    has_v1 = "scans" in tables and "findings" in tables
    has_v2 = "detector_runs" in tables
    has_v4 = "console_users" in tables
    # 必须在 executescript(DDL) 之前取：新库执行后 executions 必然存在。
    has_v5 = "executions" in tables

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

    if has_v4 and not has_v5:
        _migrate_v5(conn)

    _ensure_attribution_foreign_keys(conn)
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
