"""控制台认证、授权、审计与保留策略测试。

重点在安全属性而不是 happy path：未认证一律 401（含不存在的 /api 路由，
否则可用来探测端点）、角色不足 403、登出即失效、设备令牌不能冒充控制台
会话、口令与令牌不落库也不进审计、保留策略不误删仍在被引用的 Finding。
"""

from __future__ import annotations

import importlib
import threading
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
import pytest
from pydantic import ValidationError

from domain import ActorKind, AuditEvent, AuditOutcome, ConsoleRole, DeviceStatus, RetentionKind
from services.auth_service import AuthError, AuthService
from storage.repositories import RetentionRepository, Storage

VIEWER_PASSWORD = "viewer-passphrase-1234"
OPERATOR_PASSWORD = "operator-passphrase-1234"
ADMIN_PASSWORD = "admin-passphrase-1234"


@pytest.fixture()
def api(tmp_path, monkeypatch):
    """起一个绑到临时库的真实 HTTP 服务。

    server 模块在 import 时就按环境变量绑定数据库和扫描目录，所以必须先设
    环境变量再 reload，每个测试拿到独立的库。
    """
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "sample.py").write_text("import os\n", encoding="utf-8")
    monkeypatch.setenv("FUSION_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("FUSION_SCAN_ROOT", str(workspace))
    monkeypatch.setenv("FUSION_BIND", "127.0.0.1")
    monkeypatch.setenv("ASGP_MODEL_PROVIDER", "stepfun")

    module = importlib.import_module("server")
    module = importlib.reload(module)

    server = module.ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield SimpleNamespace(
            module=module,
            base=f"http://127.0.0.1:{server.server_port}",
            db_path=tmp_path / "test.db",
            workspace=workspace,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def call(base: str, method: str, path: str, *, token: str | None = None,
         body: dict | None = None, cookies: dict | None = None) -> httpx.Response:
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    with httpx.Client(cookies=cookies or {}) as client:
        return client.request(method, base + path, headers=headers, json=body, timeout=15)


def login(base: str, username: str = "admin", password: str = ADMIN_PASSWORD) -> str:
    response = call(base, "POST", "/api/session", body={"username": username,
                                                        "password": password})
    assert response.status_code == 200, response.text
    return response.json()["token"]


@pytest.fixture()
def admin_token(api):
    """引导管理员并用它登录。"""
    username, password = api.module.auth_service.bootstrap_admin(password=ADMIN_PASSWORD)
    assert (username, password) == ("admin", ADMIN_PASSWORD)
    return login(api.base)


# ---------- 未认证与授权 ----------

@pytest.mark.parametrize("method,path,body", [
    ("GET", "/api/summary", None),
    ("GET", "/api/scans", None),
    ("GET", "/api/engines", None),
    ("GET", "/api/providers", None),
    ("GET", "/api/users", None),
    ("GET", "/api/devices", None),
    ("GET", "/api/audit", None),
    ("GET", "/api/retention", None),
    ("GET", "/api/health", None),
    ("POST", "/api/scans", {"target": "sample.py"}),
    ("POST", "/api/providers/stepfun/probe", None),
    ("POST", "/api/users", {"username": "x", "password": "y"}),
    ("DELETE", "/api/session", None),
    ("PATCH", "/api/users/user_x", {"role": "admin"}),
])
def test_unauthenticated_requests_are_rejected(api, method, path, body):
    response = call(api.base, method, path, body=body)
    assert response.status_code == 401, response.text
    # 401 必须带 WWW-Authenticate，客户端才知道该用哪种方案重试。
    assert "www-authenticate" in {k.lower() for k in response.headers}
    assert "error" in response.json()


def test_unknown_api_route_also_requires_auth(api):
    """不存在的 /api 路由也要 401，否则未认证请求可用来探测端点是否存在。"""
    response = call(api.base, "GET", "/api/definitely-not-a-real-endpoint")
    assert response.status_code == 401


def test_static_pages_and_login_stay_public(api):
    assert call(api.base, "GET", "/").status_code == 200
    response = call(api.base, "POST", "/api/session",
                    body={"username": "nobody", "password": "whatever"})
    assert response.status_code == 401


def test_wrong_password_is_rejected_without_user_enumeration(api):
    api.module.auth_service.bootstrap_admin(password=ADMIN_PASSWORD)
    missing_user = call(api.base, "POST", "/api/session",
                        body={"username": "ghost", "password": "whatever"})
    wrong_password = call(api.base, "POST", "/api/session",
                          body={"username": "admin", "password": "whatever"})
    assert missing_user.status_code == wrong_password.status_code == 401
    assert missing_user.json()["error"] == wrong_password.json()["error"]


def test_session_probe_reports_current_user(api, admin_token):
    """前端用 GET /api/session 判断会话是否仍有效。"""
    anonymous = call(api.base, "GET", "/api/session")
    assert anonymous.status_code == 401

    session = call(api.base, "GET", "/api/session", token=admin_token).json()
    assert session["username"] == "admin"
    assert session["role"] == "admin"


def test_viewer_can_read_but_not_scan(api, admin_token):
    user_id = api.module.auth_service.create_user(
        actor=api.module.auth_service.authenticate(admin_token)[0],
        username="viewer", password=VIEWER_PASSWORD, role=ConsoleRole.VIEWER)
    assert user_id
    token = login(api.base, "viewer", VIEWER_PASSWORD)

    assert call(api.base, "GET", "/api/summary", token=token).status_code == 200
    denied = call(api.base, "POST", "/api/scans",
                  token=token, body={"target": "sample.py"})
    assert denied.status_code == 403
    assert "scan" in denied.json()["error"]


def test_operator_cannot_manage_users_or_retention(api, admin_token):
    actor = api.module.auth_service.authenticate(admin_token)[0]
    api.module.auth_service.create_user(actor=actor, username="operator",
                                        password=OPERATOR_PASSWORD,
                                        role=ConsoleRole.OPERATOR)
    token = login(api.base, "operator", OPERATOR_PASSWORD)

    # operator 可以扫描和导入。
    assert call(api.base, "POST", "/api/scans/import", token=token,
                body={"report": {"findings": []}, "target": "sample.py"}).status_code == 201
    # 但不能管用户、设备、审计和保留策略。
    for method, path, body in [
        ("GET", "/api/users", None),
        ("POST", "/api/users", {"username": "nope", "password": "nope-nope-1234"}),
        ("GET", "/api/audit", None),
        ("POST", "/api/retention", {"data_kind": "detector_runs", "retention_days": 30}),
        ("POST", "/api/retention/prune", None),
    ]:
        assert call(api.base, method, path, token=token, body=body).status_code == 403


def test_admin_can_read_audit(api, admin_token):
    response = call(api.base, "GET", "/api/audit", token=admin_token)
    assert response.status_code == 200
    assert response.json()["events"]


# ---------- 会话生命周期 ----------

def test_logout_revokes_the_session(api, admin_token):
    assert call(api.base, "DELETE", "/api/session", token=admin_token).status_code == 200
    after = call(api.base, "GET", "/api/summary", token=admin_token)
    assert after.status_code == 401


def test_cookie_session_authenticates(api, admin_token):
    """浏览器不带 Authorization 头，只靠 HttpOnly Cookie。"""
    response = call(api.base, "GET", "/api/summary",
                    cookies={"asgp_session": admin_token})
    assert response.status_code == 200


def test_session_cookie_is_hardened(api):
    api.module.auth_service.bootstrap_admin(password=ADMIN_PASSWORD)
    response = call(api.base, "POST", "/api/session",
                    body={"username": "admin", "password": ADMIN_PASSWORD})
    cookie = response.headers["set-cookie"]
    assert "HttpOnly" in cookie
    assert "SameSite=Strict" in cookie
    assert "Path=/" in cookie
    assert "Max-Age=" in cookie


def test_disabled_user_loses_access_immediately(api, admin_token):
    actor = api.module.auth_service.authenticate(admin_token)[0]
    user_id = api.module.auth_service.create_user(
        actor=actor, username="viewer", password=VIEWER_PASSWORD,
        role=ConsoleRole.VIEWER)
    token = login(api.base, "viewer", VIEWER_PASSWORD)
    assert call(api.base, "GET", "/api/summary", token=token).status_code == 200

    # 停用账号必须同时吊销已发出的会话。
    patched = call(api.base, "PATCH", f"/api/users/{user_id}", token=admin_token,
                   body={"disabled": True})
    assert patched.status_code == 200
    assert call(api.base, "GET", "/api/summary", token=token).status_code == 403


def test_admin_cannot_demote_or_disable_itself(api, admin_token):
    actor = api.module.auth_service.authenticate(admin_token)[0]
    for body in ({"role": "viewer"}, {"disabled": True}):
        response = call(api.base, "PATCH", f"/api/users/{actor.user_id}",
                        token=admin_token, body=body)
        assert response.status_code == 403


def test_change_password_invalidates_old_credentials(api, admin_token):
    actor = api.module.auth_service.authenticate(admin_token)[0]
    user_id = api.module.auth_service.create_user(
        actor=actor, username="viewer", password=VIEWER_PASSWORD,
        role=ConsoleRole.VIEWER)
    changed = call(api.base, "POST", f"/api/users/{user_id}/password", token=admin_token,
                   body={"old_password": VIEWER_PASSWORD,
                         "new_password": "brand-new-passphrase-9999"})
    assert changed.status_code == 200
    assert call(api.base, "POST", "/api/session",
                body={"username": "viewer", "password": VIEWER_PASSWORD}).status_code == 401
    assert login(api.base, "viewer", "brand-new-passphrase-9999")


def test_short_password_is_rejected(api, admin_token):
    response = call(api.base, "POST", "/api/users", token=admin_token,
                    body={"username": "shorty", "password": "tooshort"})
    assert response.status_code == 400


# ---------- 设备身份 ----------

def test_device_token_is_not_a_console_session(api, admin_token):
    enrolled = call(api.base, "POST", "/api/devices", token=admin_token,
                    body={"label": "lab-mac"})
    assert enrolled.status_code == 201
    device_token = enrolled.json()["token"]

    # 设备令牌证明的是上报资格，不是控制台用户权限。
    assert call(api.base, "GET", "/api/summary", token=device_token).status_code == 401
    assert call(api.base, "GET", "/api/users", token=device_token).status_code == 401


def test_suspended_device_cannot_report(api):
    auth = AuthService(storage=Storage(api.db_path))
    auth.bootstrap_admin(password=ADMIN_PASSWORD)
    admin = auth.authenticate(login(api.base))[0]
    enrolled = auth.enroll_device(actor=admin, label="lab-mac")
    assert auth.resolve_device(enrolled["token"]).can_report()

    auth.set_device_status(actor=admin, device_id=enrolled["device_id"],
                           status=DeviceStatus.SUSPENDED)
    with pytest.raises(AuthError) as excinfo:
        auth.resolve_device(enrolled["token"])
    assert excinfo.value.kind == "forbidden"


# ---------- 审计 ----------

def test_audit_records_actor_outcome_and_request_id(api, admin_token):
    call(api.base, "GET", "/api/summary", token=admin_token)
    call(api.base, "GET", "/api/summary")  # 未认证
    events = call(api.base, "GET", "/api/audit", token=admin_token).json()["events"]

    outcomes = {(event["actor_kind"], event["outcome"]) for event in events}
    assert ("console_user", "success") in outcomes
    assert ("anonymous", "denied") in outcomes
    for event in events:
        assert event["request_id"]
        assert event["action"].startswith(("GET", "POST", "DELETE", "PATCH"))


def test_audit_never_records_credentials(api, admin_token):
    """口令和令牌都不能出现在审计记录或数据库文件里。"""
    actor = api.module.auth_service.authenticate(admin_token)[0]
    api.module.auth_service.create_user(actor=actor, username="viewer",
                                        password=VIEWER_PASSWORD,
                                        role=ConsoleRole.VIEWER)
    login(api.base, "viewer", VIEWER_PASSWORD)
    call(api.base, "GET", "/api/summary", token=admin_token)

    storage = Storage(api.db_path)
    rows = storage.connection().execute("SELECT detail FROM audit_events").fetchall()
    blob = " ".join(row["detail"] for row in rows)
    assert VIEWER_PASSWORD not in blob
    assert admin_token not in blob

    raw = api.db_path.read_bytes()
    assert VIEWER_PASSWORD.encode() not in raw
    assert admin_token.encode() not in raw


def test_anonymous_success_is_rejected_by_the_contract():
    with pytest.raises(ValidationError):
        AuditEvent(
            audit_id="aud_1",
            occurred_at=datetime.now(timezone.utc),
            request_id="req_1",
            actor_kind=ActorKind.ANONYMOUS,
            actor_id="anonymous",
            action="GET /api/summary",
            outcome=AuditOutcome.SUCCESS,
        )


# ---------- 保留策略 ----------

def test_bootstrap_admin_creates_no_default_credential(tmp_path):
    auth = AuthService(storage=Storage(tmp_path / "auth.db"))
    first = auth.bootstrap_admin()
    assert first is not None
    username, password = first
    assert username == "admin"
    # 一次性随机口令，不是任何默认值。
    assert len(password) >= 20
    assert password not in ("admin", "password", "asgp", "changeme")
    # 已有用户时不再重复创建。
    assert auth.bootstrap_admin() is None
    assert auth.login(username=username, password=password)["username"] == "admin"


def test_retention_prune_preserves_findings_shared_with_retained_runs(api):
    """ originating run 过期不能牵连仍在保留期内其它 run 引用的 Finding。"""
    module = api.module
    service = module.scan_service
    storage = module.storage

    old_run = service.import_report(
        detector_id="imported-report", target_ref="sample.py",
        report={"findings": [{"rule_id": "R1", "message": "shared issue",
                              "level": "error", "locations": []}]},
        idempotency_key="old-run",
    )["detector_run_id"]
    new_run = service.import_report(
        detector_id="imported-report", target_ref="sample.py",
        report={"findings": [{"rule_id": "R1", "message": "shared issue",
                              "level": "error", "locations": []}]},
        idempotency_key="new-run",
    )["detector_run_id"]

    # 两次 run 应共用同一个 Finding（按 detector_id + fingerprint 去重）。
    with storage.connection() as conn:
        finding_ids = {row["finding_id"] for row in conn.execute(
            "SELECT finding_id FROM findings").fetchall()}
        assert len(finding_ids) == 1
        shared_id = finding_ids.pop()

    # 把旧 run 推到保留期之外，新 run 留在保留期内。
    long_ago = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
    with storage.connection() as conn:
        conn.execute("UPDATE detector_runs SET started_at = ? WHERE detector_run_id = ?",
                     (long_ago, old_run))

    counts = RetentionRepository(storage).prune(now=datetime.now(timezone.utc))

    with storage.connection() as conn:
        assert conn.execute("SELECT 1 FROM detector_runs WHERE detector_run_id = ?",
                            (old_run,)).fetchone() is None
        assert conn.execute("SELECT 1 FROM detector_runs WHERE detector_run_id = ?",
                            (new_run,)).fetchone() is not None
        # 关键断言：Finding 仍在，且仍与新 run 关联。
        assert conn.execute("SELECT 1 FROM findings WHERE finding_id = ?",
                            (shared_id,)).fetchone() is not None
        assert conn.execute(
            "SELECT 1 FROM detector_run_findings WHERE detector_run_id = ? AND finding_id = ?",
            (new_run, shared_id)).fetchone() is not None
        # 来源指向已删除的 run 的引用必须被置空，不能留悬空 ID。
        assert conn.execute("SELECT detector_run_id FROM findings WHERE finding_id = ?",
                            (shared_id,)).fetchone()["detector_run_id"] is None
    assert counts["detector_runs"] >= 1


def test_retention_prune_deletes_truly_orphaned_findings(api):
    module = api.module
    storage = module.storage
    run_id = module.scan_service.import_report(
        detector_id="imported-report", target_ref="sample.py",
        report={"findings": [{"rule_id": "R9", "message": "lonely issue",
                              "level": "error", "locations": []}]},
        idempotency_key="orphan-run",
    )["detector_run_id"]
    with storage.connection() as conn:
        finding_id = conn.execute("SELECT finding_id FROM findings").fetchone()["finding_id"]

    long_ago = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
    with storage.connection() as conn:
        conn.execute("UPDATE detector_runs SET started_at = ? WHERE detector_run_id = ?",
                     (long_ago, run_id))

    RetentionRepository(storage).prune(now=datetime.now(timezone.utc))
    with storage.connection() as conn:
        assert conn.execute("SELECT 1 FROM findings WHERE finding_id = ?",
                            (finding_id,)).fetchone() is None
        assert conn.execute("SELECT 1 FROM raw_reports WHERE detector_run_id = ?",
                            (run_id,)).fetchone() is None


def test_retention_rule_round_trip_through_api(api, admin_token):
    response = call(api.base, "POST", "/api/retention", token=admin_token,
                    body={"data_kind": "detector_runs", "retention_days": 7,
                          "enabled": False})
    assert response.status_code == 200
    rules = {rule["data_kind"]: rule
             for rule in call(api.base, "GET", "/api/retention",
                              token=admin_token).json()["rules"]}
    assert rules["detector_runs"]["retention_days"] == 7
    assert not rules["detector_runs"]["enabled"]

    bad_kind = call(api.base, "POST", "/api/retention", token=admin_token,
                    body={"data_kind": "not_a_kind", "retention_days": 7})
    assert bad_kind.status_code == 400
    bad_days = call(api.base, "POST", "/api/retention", token=admin_token,
                    body={"data_kind": "detector_runs", "retention_days": 0})
    assert bad_days.status_code == 400


def test_disabled_retention_rule_is_not_pruned(api):
    module = api.module
    storage = module.storage
    module.scan_service.import_report(
        detector_id="imported-report", target_ref="sample.py",
        report={"findings": [{"rule_id": "R2", "message": "kept issue",
                              "level": "error", "locations": []}]},
        idempotency_key="kept-run",
    )
    RetentionRepository(storage).set_rule(
        data_kind=RetentionKind.DETECTOR_RUNS, retention_days=1, enabled=False)
    long_ago = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
    with storage.connection() as conn:
        conn.execute("UPDATE detector_runs SET started_at = ?", (long_ago,))

    RetentionRepository(storage).prune(now=datetime.now(timezone.utc))
    with storage.connection() as conn:
        assert conn.execute("SELECT COUNT(*) FROM detector_runs").fetchone()[0] == 1


# ---------- 服务层 ----------

def test_auth_service_rejects_unknown_role(tmp_path):
    auth = AuthService(storage=Storage(tmp_path / "auth.db"))
    with pytest.raises(AuthError):
        auth.login(username="admin", password="whatever")


def test_purge_expired_sessions_removes_only_dead_ones(tmp_path):
    auth = AuthService(storage=Storage(tmp_path / "auth.db"))
    auth.bootstrap_admin(password=ADMIN_PASSWORD)
    token = auth.login(username="admin", password=ADMIN_PASSWORD)["token"]
    assert auth.authenticate(token)[0].username == "admin"

    past = datetime.now(timezone.utc) - timedelta(seconds=1)
    assert auth.purge_expired_sessions(now=past) == 0  # 未过期，不误删
    assert auth.authenticate(token)[0].username == "admin"

    future = datetime.now(timezone.utc) + timedelta(days=365)
    assert auth.purge_expired_sessions(now=future) == 1
    with pytest.raises(AuthError):
        auth.authenticate(token)
