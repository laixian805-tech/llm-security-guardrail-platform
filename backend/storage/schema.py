"""ASGP 存储 schema 与迁移。

当前用 SQLite 开发；多设备正式环境迁 PostgreSQL。表结构按 DATA_MODEL.md
的领域实体拆，不再复用旧原型把资产、事件、扫描塞在一张表的做法。

去重约束落在数据库层：findings 对 (detector_id, fingerprint) 唯一，
重扫同一目标不会积累重复 Finding；detector_runs 的 idempotency_key
唯一，调用方重试不会重复登记同一次执行。
"""

from __future__ import annotations

import json
import sqlite3

SCHEMA_VERSION = 12

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
    -- 版本声明的证据等级：registry / binary_changed / device_claim。
    -- 与 product_version 分开存，因为"报了什么"和"这个值可不可信"是两个
    -- 事实；只存版本号就无法区分"权威核过"与"设备自称"。
    product_version_source TEXT NOT NULL DEFAULT 'device_claim',
    session_id TEXT NOT NULL,
    -- P1 无资产注册表：只存端点上报的引用，不做存在性校验。v8 建了
    -- assets/asset_instances 台账，但存量自由文本引用不回溯校验。
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
    source_kind TEXT,
    source_ref TEXT,
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
    -- 逐维度计算依据（score/confidence/rule_version/basis/evidence_refs）。
    -- 没有这一列，"Intrinsic 为什么是 95"只能靠翻代码回答。
    dimensions TEXT NOT NULL DEFAULT '[]',
    evidence_refs TEXT NOT NULL DEFAULT '[]',
    rule_version TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- 端侧上报的覆盖度对账。没有这张表，"Hook 丢失率"和"Audit 丢失率"永远
-- 只是说法而不是数字：丢数据发生在端侧 outbox 容量封顶的那一刻，服务端
-- 只看到"没有事件"，分不清"没发生"和"丢了"。
CREATE TABLE IF NOT EXISTS coverage_reports (
    report_id TEXT PRIMARY KEY,
    host_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    collector_id TEXT NOT NULL,
    period_start TEXT NOT NULL,
    period_end TEXT NOT NULL,
    delivered INTEGER NOT NULL DEFAULT 0,
    dead INTEGER NOT NULL DEFAULT 0,
    dropped TEXT NOT NULL DEFAULT '{}',
    dropped_records INTEGER NOT NULL DEFAULT 0,
    unbounded_gaps TEXT NOT NULL DEFAULT '[]',
    backlog INTEGER NOT NULL DEFAULT 0,
    high_water_seq INTEGER NOT NULL DEFAULT 0,
    received_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS coverage_reports_host ON coverage_reports(host_id, received_at);

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
    -- 目标产品：决定 commit 落到哪个真实技能目录。NULL 表示只进平台托管存储。
    product_id TEXT,
    product_target TEXT,
    product_rollback_ref TEXT,
    product_loaded INTEGER,
    product_verification TEXT,
    state TEXT NOT NULL,
    approved_by TEXT,
    observed_content_hash TEXT,
    -- 安装器回滚凭据：NULL 表示从未提交；否则是提交前快照名或 first_install。
    rollback_ref TEXT,
    failure_reason TEXT,
    transaction_id TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- 资产台账（v8）。Asset 是逻辑治理对象，AssetInstance 是某主机/产品/作用域
-- 中的具体副本，AssetRelease 是可验证内容版本。三者分开：同一个 Skill 在
-- Claude Code 和 Codex 下共享 logical asset，但是不同 instance；instance
-- 相同也不保证当前内容与上次扫描一致。
CREATE TABLE IF NOT EXISTS assets (
    asset_id TEXT PRIMARY KEY,
    asset_type TEXT NOT NULL,
    canonical_name TEXT NOT NULL,
    product TEXT,
    publisher TEXT,
    namespace TEXT,
    provenance TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS asset_instances (
    instance_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    host_id TEXT NOT NULL,
    product_scope TEXT NOT NULL,
    install_path TEXT,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    -- 同一资产在同一主机同一产品作用域只有一条实例记录。
    UNIQUE (asset_id, host_id, product_scope)
);

CREATE TABLE IF NOT EXISTS publishers (
    publisher_id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    algorithm TEXT NOT NULL DEFAULT 'ed25519',
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL,
    revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS asset_releases (
    release_id TEXT PRIMARY KEY,
    asset_id TEXT NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    version TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    source_uri TEXT,
    publisher_id TEXT REFERENCES publishers(publisher_id),
    signature TEXT,
    -- 只能由服务端使用 publishers 公钥对 content_hash 做 Ed25519 验签写入。
    signature_verified INTEGER NOT NULL DEFAULT 0,
    verified_at TEXT,
    published_at TEXT,
    UNIQUE (asset_id, version, content_hash)
);

-- 分析员显式建立的 执行 ↔ 发现项 关联。这不是自动归因：时间线里按
-- analyst_linked 标注，避免被误读成采集器证明的因果。
CREATE TABLE IF NOT EXISTS execution_findings (
    execution_id TEXT NOT NULL REFERENCES executions(execution_id) ON DELETE CASCADE,
    finding_id TEXT NOT NULL REFERENCES findings(finding_id) ON DELETE CASCADE,
    actor_id TEXT NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    PRIMARY KEY (execution_id, finding_id)
);

-- 策略版本：evaluate 必须记录实际生效的版本，规则依序首个命中者胜出。
CREATE TABLE IF NOT EXISTS policy_versions (
    policy_version TEXT PRIMARY KEY,
    rules TEXT NOT NULL DEFAULT '[]',
    status TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    activated_at TEXT,
    retired_at TEXT
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
    actor_id TEXT NOT NULL, action TEXT NOT NULL, occurred_at TEXT NOT NULL,
    -- 迁移原因：回滚、驳回这类动作必须能解释"为什么"，否则审计只能看到发生了什么。
    detail TEXT
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
CREATE INDEX IF NOT EXISTS assets_type ON assets(asset_type, updated_at);
CREATE INDEX IF NOT EXISTS assets_name ON assets(canonical_name);
CREATE INDEX IF NOT EXISTS asset_instances_asset ON asset_instances(asset_id, last_seen_at);
CREATE INDEX IF NOT EXISTS asset_instances_host ON asset_instances(host_id, last_seen_at);
CREATE INDEX IF NOT EXISTS asset_releases_asset ON asset_releases(asset_id, published_at);
CREATE INDEX IF NOT EXISTS execution_findings_finding ON execution_findings(finding_id);
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


def _migrate_v7(conn: sqlite3.Connection) -> None:
    """v6 → v7：准入记录带安装器回滚凭据，并建立策略版本表。

    rollback_ref 让回滚有确定目标（恢复哪个快照、还是移除首次安装）；
    策略版本表由默认活跃版本播种，evaluate 不再写死 policy-v1。
    """
    columns = {row[1] for row in conn.execute("PRAGMA table_info(admissions)")}
    if "rollback_ref" not in columns:
        conn.execute("ALTER TABLE admissions ADD COLUMN rollback_ref TEXT")
    from domain.governance import default_rule_set

    if not conn.execute("SELECT 1 FROM policy_versions WHERE status='active'").fetchone():
        model = default_rule_set()
        conn.execute(
            "INSERT INTO policy_versions (policy_version, rules, status, created_by, created_at, activated_at)"
            " VALUES (?,?,?,?,?,?)",
            (model.policy_version, json.dumps([rule.model_dump(mode="json") for rule in model.rules]),
             model.status.value, model.created_by, model.created_at.isoformat(), model.activated_at.isoformat()),
        )


def _migrate_v8(conn: sqlite3.Connection) -> None:
    """v7 → v8：准入记录声明目标产品。

    product_id 让 commit 有确定的产品加载目录（~/.claude/skills 等）。历史
    记录保持 NULL，表示当时只进平台托管存储；不回溯改写既有验收结论。
    """
    columns = {row[1] for row in conn.execute("PRAGMA table_info(admissions)")}
    if "product_id" not in columns:
        conn.execute("ALTER TABLE admissions ADD COLUMN product_id TEXT")
    if "product_target" not in columns:
        conn.execute("ALTER TABLE admissions ADD COLUMN product_target TEXT")
    if "product_rollback_ref" not in columns:
        conn.execute("ALTER TABLE admissions ADD COLUMN product_rollback_ref TEXT")
    if "product_loaded" not in columns:
        conn.execute("ALTER TABLE admissions ADD COLUMN product_loaded INTEGER")
    if "product_verification" not in columns:
        conn.execute("ALTER TABLE admissions ADD COLUMN product_verification TEXT")


def _migrate_v9(conn: sqlite3.Connection) -> None:
    """v8 → v9：状态迁移记录可携带原因。

    策略回滚是"出事时的退路"，只记 from/to 和 actor 不足以复盘——必须能说明
    为什么退。历史记录保持 NULL，不回溯补造原因。
    """
    columns = {row[1] for row in conn.execute("PRAGMA table_info(governance_transitions)")}
    if "detail" not in columns:
        conn.execute("ALTER TABLE governance_transitions ADD COLUMN detail TEXT")


def _migrate_v10(conn: sqlite3.Connection) -> None:
    """v9 → v10：执行记录带上版本声明的证据等级。

    旧行的 product_version 是设备自称的，没有任何权威核过，所以一律记为
    device_claim——不回溯补一个"已核验"的结论。新行由摄入边界按注册表判定。
    """
    columns = {row[1] for row in conn.execute("PRAGMA table_info(executions)")}
    if "product_version_source" not in columns:
        conn.execute(
            "ALTER TABLE executions ADD COLUMN product_version_source"
            " TEXT NOT NULL DEFAULT 'device_claim'")


def _migrate_v11(conn: sqlite3.Connection) -> None:
    """v10 → v11：publishers 公钥表与 asset_releases 服务端验签证据列。

    旧版本允许客户端自报 signature_verified=true，没有密码学签名作证。
    迁移时清理无签名支撑的历史自报已验签标记，避免伪证据继续展示。
    """
    columns = {row[1] for row in conn.execute("PRAGMA table_info(asset_releases)")}
    if "publisher_id" not in columns:
        conn.execute("ALTER TABLE asset_releases ADD COLUMN publisher_id TEXT REFERENCES publishers(publisher_id)")
    if "signature" not in columns:
        conn.execute("ALTER TABLE asset_releases ADD COLUMN signature TEXT")
    if "verified_at" not in columns:
        conn.execute("ALTER TABLE asset_releases ADD COLUMN verified_at TEXT")
    conn.execute(
        "UPDATE asset_releases SET signature_verified = 0, verified_at = NULL"
        " WHERE signature IS NULL OR signature = ''"
    )


def _migrate_v12(conn: sqlite3.Connection) -> None:
    """v11 → v12：Intent 记录指令来源谱系（source_kind / source_ref）。

    历史调用未采集来源时保留 NULL（即 unknown），不得替历史数据猜测来源。
    """
    columns = {row[1] for row in conn.execute("PRAGMA table_info(intents)")}
    if "source_kind" not in columns:
        conn.execute("ALTER TABLE intents ADD COLUMN source_kind TEXT")
    if "source_ref" not in columns:
        conn.execute("ALTER TABLE intents ADD COLUMN source_ref TEXT")


def _ensure_coverage_delivered(conn: sqlite3.Connection) -> None:
    """旧库升级后 coverage_reports 可能缺少 delivered 列，幂等补齐。"""
    columns = {row[1] for row in conn.execute("PRAGMA table_info(coverage_reports)")}
    if columns and "delivered" not in columns:
        conn.execute("ALTER TABLE coverage_reports ADD COLUMN delivered INTEGER NOT NULL DEFAULT 0")


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

    # v7 的步骤自带幂等判断（列存在性、是否已有活跃版本），新旧库都可执行。
    _migrate_v7(conn)
    _migrate_v8(conn)
    _migrate_v9(conn)
    _migrate_v10(conn)
    _migrate_v11(conn)
    _migrate_v12(conn)

    # v8 只新增表（assets/asset_instances/asset_releases/execution_findings），
    # DDL 的 IF NOT EXISTS 对新旧库都生效；executions/admissions 里的
    # asset_instance_id 仍是自由文本引用，不回溯加外键，否则要重建两张有存量
    # 数据的表。台账对存量引用的态度是"不校验、不猜测"，见 AssetService。
    _ensure_attribution_foreign_keys(conn)
    _ensure_coverage_delivered(conn)
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
