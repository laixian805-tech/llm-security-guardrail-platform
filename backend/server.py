"""ASGP 控制面 HTTP 服务（扫描集成原型）。

本文件只做协议适配：目标校验、响应形状和静态页面。检测器执行、归一化与
持久化在 adapters/detectors、services/scan_service 和 storage/ 中完成。

所有 /api/* 端点都需要控制台会话（登录和静态页面除外）；未认证访问返回
401，权限不足返回 403。每次请求写审计，只记 request ID 和脱敏摘要，不记
密钥。公网部署前还需完善审计保留与设备注册流程（见 IMPLEMENTATION_PLAN.md
P0 验收）。
"""

from __future__ import annotations

import json
import os
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from adapters.detectors import DetectorError
from detectors.registry import DetectorCatalog
from domain import (
    ActorKind,
    AuditOutcome,
    ConsoleRole,
    ConsoleUser,
    DeviceStatus,
    Permission,
    RetentionKind,
)
from model_providers import PROFILE_KINDS, provider_catalog
from products.registry import ProductCatalog
from services.auth_service import AuthError, AuthService
from services.provider_probe import ProviderProbeService
from services.scan_service import ScanService
from services.ingestion_service import IngestionService, IngestError
from services.timeline_service import TimelineService
from api.v1 import is_device_route, route as route_v1
from api.governance import route as route_governance
from services.governance_service import GovernanceService
from services.approval_service import ApprovalService
from services.attribution_service import AttributionService
from pydantic import ValidationError
from storage.repositories import Storage, now_iso

ROOT = Path(__file__).resolve().parents[1]
WEB_ROOT = ROOT / "web"
DATA_ROOT = ROOT / "data"
SCAN_ROOT = Path(os.environ.get("FUSION_SCAN_ROOT", str(ROOT / "workspace"))).resolve()
DB_PATH = Path(os.environ.get("FUSION_DB_PATH", str(DATA_ROOT / "fusion.db")))
BIND_HOST = os.environ.get("FUSION_BIND", "127.0.0.1")
MAX_BODY_BYTES = 8 * 1024 * 1024
SCAN_TIMEOUT_SECONDS = int(os.environ.get("FUSION_SCAN_TIMEOUT", "300"))
PROBE_TIMEOUT_SECONDS = float(os.environ.get("FUSION_PROBE_TIMEOUT", "20"))
SESSION_TTL_SECONDS = int(os.environ.get("FUSION_SESSION_TTL", str(12 * 60 * 60)))
SESSION_COOKIE = "asgp_session"
KNOWN_PROVIDERS = {"stepfun", "xunfei"}

# 运行状态 → 旧端点状态词，保持页面标签可读。
LEGACY_STATUS = {
    "succeeded": "completed",
    "imported": "imported",
    "failed": "failed",
    "timed_out": "failed",
    "output_limit_exceeded": "failed",
}

storage = Storage(DB_PATH)
probe_service = ProviderProbeService(storage=storage, timeout_seconds=PROBE_TIMEOUT_SECONDS)
auth_service = AuthService(storage=storage, session_ttl_seconds=SESSION_TTL_SECONDS)
catalog = DetectorCatalog(
    data_root=DATA_ROOT,
    timeout_seconds=SCAN_TIMEOUT_SECONDS,
    probe_status=probe_service.status_for,
)
scan_service = ScanService(storage=storage, catalog=catalog)
product_catalog = ProductCatalog()
ingestion_service = IngestionService(storage)
timeline_service = TimelineService(storage)
governance_service = GovernanceService(storage)
approval_service = ApprovalService(storage)
attribution_service = AttributionService(storage)

# 保留策略默认值先落库，否则第一次清理时读不到规则。
from storage.repositories import RetentionRepository  # noqa: E402

RetentionRepository(storage).ensure_defaults()


def _required_permission(method: str, path: str) -> Permission | None:
    """该路由需要的权限；None 表示公开（登录与静态页面）。

    未识别的 /api 路由同样要求认证，避免未认证请求用来探测端点是否存在。
    """
    if method == "POST" and path == "/api/session":
        return None
    if method in ("GET", "HEAD") and (path == "/" or path.startswith("/web/")):
        return None
    if not path.startswith("/api/"):
        return None

    if path.startswith("/api/providers/"):
        return Permission.PROBE if (method == "POST" and path.endswith("/probe")) else Permission.READ
    if path == "/api/scans" or path.startswith("/api/scans/"):
        if method == "POST" and path == "/api/scans/import":
            return Permission.IMPORT_REPORT
        if method == "GET" and path.endswith("/raw-report"):
            return Permission.READ_RAW_REPORT
        return Permission.SCAN if method == "POST" else Permission.READ
    if path in ("/api/engines", "/api/summary", "/api/providers"):
        return Permission.READ
    # /api/v1 下的设备上报端点走设备令牌认证，不经过本权限表；此处只覆盖
    # 控制台读的产品能力矩阵。
    if path == "/api/v1/products":
        return Permission.READ
    if path.startswith(('/api/v1/approvals','/api/v1/risk-assessments','/api/v1/policies/',
                        '/api/v1/policy-decisions','/api/v1/admissions','/api/v1/incidents')):
        return Permission.READ if method == 'GET' else Permission.GOVERN
    if path.endswith('/correlate'):
        return Permission.GOVERN
    if path == "/api/users" or path.startswith("/api/users/"):
        return Permission.MANAGE_USERS
    if path == "/api/devices" or path.startswith("/api/devices/"):
        return Permission.MANAGE_USERS
    if path == "/api/audit":
        return Permission.READ_AUDIT
    if path.startswith("/api/retention"):
        return Permission.MANAGE_RETENTION if method in ("POST", "PUT") else Permission.READ
    return Permission.READ


def _safe_target(raw: Any) -> Path:
    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("目标路径必须是 workspace/ 下的相对路径。")
    candidate = Path(raw)
    if candidate.is_absolute():
        raise ValueError("不接受绝对路径，请填写 workspace/ 下的相对路径。")
    resolved = (SCAN_ROOT / candidate).resolve()
    if resolved != SCAN_ROOT and SCAN_ROOT not in resolved.parents:
        raise ValueError("目标路径不能越出 workspace/ 扫描目录。")
    if not resolved.exists():
        raise ValueError("workspace/ 下找不到该目标。")
    return resolved


def _engine_rows() -> list[dict[str, Any]]:
    """引擎清单：能力描述来自适配器，运行状态来自 health_check。"""
    health = catalog.health()
    rows = []
    for descriptor in catalog.descriptors():
        report = health[descriptor.detector_id]
        rows.append({
            "id": descriptor.detector_id,
            "binary": descriptor.detector_id,
            "source": descriptor.upstream_source,
            "license": descriptor.license_id,
            "purpose": descriptor.boundary,
            "boundary": descriptor.boundary,
            "available": report["installed"],
            "runnable": report["runnable"],
            "executable": "",
            "version": descriptor.version,
            "llm_required": descriptor.llm_required,
            "input_types": descriptor.input_types,
        })
    return rows


def _split_location(uri: str) -> tuple[str, int]:
    if ":" in uri:
        path, _, line = uri.rpartition(":")
        if line.isdigit():
            return path, int(line)
    return uri, 0


def _legacy_run(row: dict[str, Any]) -> dict[str, Any]:
    by_severity: dict[str, int] = {}
    for finding in scan_service.runs.findings_for_run(row["detector_run_id"]):
        by_severity[finding["severity"]] = by_severity.get(finding["severity"], 0) + 1
    return {
        "scan_id": row["detector_run_id"],
        "engine": row["detector_id"],
        "target": row["target_ref"],
        "status": LEGACY_STATUS.get(row["status"], row["status"]),
        "started_at": row["started_at"],
        "finished_at": row["finished_at"],
        "finding_count": row["finding_count"],
        "summary": {"finding_count": row["finding_count"], "by_severity": by_severity},
        "detector_id": row["detector_id"],
        "detector_version": row["detector_version"],
        "error": row["error"],
    }


def _legacy_finding(row: dict[str, Any]) -> dict[str, Any]:
    evidence = json.loads(row["evidence_refs"] or "[]")
    uri = evidence[0]["uri"] if evidence else ""
    file, line = _split_location(uri)
    return {
        "finding_id": row["finding_id"],
        "engine": row["detector_id"],
        "rule_id": row["rule_id"],
        "title": row["title"],
        "severity": row["severity"],
        "message": row["message"],
        "file": file,
        "line": line,
        "risk_score": row["upstream_risk_score"],
        "metadata": {},
        "fingerprint": row["fingerprint"],
        "confidence": row["confidence"],
        "detector_version": row["detector_version"],
        "upstream_rule_id": row["upstream_rule_id"],
    }


class Handler(BaseHTTPRequestHandler):
    server_version = "ASGP/0.3"

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[{now_iso()}] {fmt % args}")

    # ---------- 基础设施 ----------

    def _send(self, status: int, payload: Any, content_type: str = "application/json; charset=utf-8",
              extra_headers: dict[str, str] | None = None) -> None:
        self._status_sent = status
        body = payload if isinstance(payload, bytes) else json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        maximum = 16 * 1024 * 1024 if self.path.startswith("/api/v1/") else MAX_BODY_BYTES
        if length <= 0 or length > maximum:
            raise ValueError("invalid_body_size")
        raw = self.rfile.read(length)
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("请求内容必须是 JSON 对象。")
        return value

    def _token(self) -> str:
        """从 Authorization 头或会话 Cookie 取令牌。"""
        header = self.headers.get("Authorization") or ""
        scheme, _, value = header.partition(" ")
        if scheme.lower() == "bearer" and value.strip():
            return value.strip()
        cookie_header = self.headers.get("Cookie") or ""
        if cookie_header:
            jar = SimpleCookie()
            try:
                jar.load(cookie_header)
            except Exception:
                return ""
            morsel = jar.get(SESSION_COOKIE)
            if morsel is not None:
                return morsel.value
        return ""

    def _session_cookie(self, token: str, *, max_age: int) -> str:
        secure = " Secure;" if self.headers.get("X-Forwarded-Proto") == "https" else ""
        return (f"{SESSION_COOKIE}={token}; HttpOnly; SameSite=Strict; Path=/;"
                f" Max-Age={max_age}{secure}")

    # ---------- 认证与审计 ----------

    def _dispatch(self, method: str) -> None:
        """统一入口：认证 → 鉴权 → 路由 → 审计。"""
        parsed = urlparse(self.path)
        path = parsed.path
        request_id = uuid.uuid4().hex[:16]
        self._status_sent = 500
        self._user = None
        self._session_row = None
        self._device = None
        self._request_id = request_id

        permission = _required_permission(method, path)
        actor_kind = ActorKind.ANONYMOUS
        actor_id = "anonymous"
        user = None
        try:
            if path.startswith("/api/v1/") and os.environ.get("ASGP_V1_ENABLED", "1") == "0":
                raise IngestError("v1_disabled", 503)
            if is_device_route(method, path):
                header = self.headers.get("Authorization", "")
                scheme, _, token = header.partition(" ")
                self._device = auth_service.resolve_device(token.strip() if scheme.lower() == "bearer" else "")
                actor_kind, actor_id = ActorKind.DEVICE, self._device.device_id
            elif permission is not None:
                user, session_row = auth_service.authenticate(self._token())
                self._user = user
                self._session_row = session_row
                actor_kind = ActorKind.CONSOLE_USER
                actor_id = user.username
                auth_service.require(user, permission)

            if path.startswith('/api/v1/executions/') and path.endswith('/correlate') and method == 'POST':
                execution_id = path.split('/')[4]
                self._send(200, attribution_service.correlate(execution_id))
            elif path.startswith('/api/v1/executions/') and path.endswith('/attributions') and method == 'GET':
                execution_id = path.split('/')[4]
                self._send(200, {'attributions': attribution_service.list(execution_id)})
            elif route_governance(self, method, parsed, governance_service, approval_service):
                pass
            elif route_v1(self, method, parsed, ingestion_service, timeline_service):
                pass
            elif method == "GET":
                self._route_get(parsed)
            elif method == "POST":
                self._route_post(parsed)
            elif method == "DELETE":
                self._route_delete(parsed)
            elif method == "PATCH":
                self._route_patch(parsed)
            else:
                self._send(405, {"error": "不支持的请求方法。"})

            auth_service.audit(
                request_id=request_id, actor_kind=actor_kind, actor_id=actor_id,
                action=f"{method} {path}", resource=path,
                outcome=AuditOutcome.SUCCESS, detail={"status": self._status_sent},
            )
        except AuthError as exc:
            status = 401 if exc.kind == "unauthenticated" else 403
            self._send(status, {"error": exc.detail, "request_id": request_id},
                       extra_headers={"WWW-Authenticate": "Bearer"} if status == 401 else None)
            auth_service.audit(
                request_id=request_id, actor_kind=actor_kind, actor_id=actor_id,
                action=f"{method} {path}", resource=path, outcome=AuditOutcome.DENIED,
                detail={"reason": exc.kind},
            )
        except (IngestError, ValidationError) as exc:
            code = exc.code if isinstance(exc, IngestError) else "invalid_payload"
            status = exc.status if isinstance(exc, IngestError) else 400
            self._send(status, {"error": {"code": code, "request_id": request_id}})
            auth_service.audit(request_id=request_id, actor_kind=actor_kind, actor_id=actor_id,
                action=f"{method} {path}", resource=path, outcome=AuditOutcome.ERROR, detail={"code": code})
        except ValueError as exc:
            self._send(400, {"error": "invalid_payload" if path.startswith("/api/v1/") else str(exc), "request_id": request_id})
            auth_service.audit(
                request_id=request_id, actor_kind=actor_kind, actor_id=actor_id,
                action=f"{method} {path}", resource=path, outcome=AuditOutcome.ERROR,
                detail={"reason": "invalid_request"},
            )
        except DetectorError as exc:
            # 目标形态/凭据问题是请求问题；超时、退出码、解析失败是执行问题。
            client_side = exc.kind.value in ("invalid_target", "missing_credential", "not_installed")
            status = 400 if client_side else 409
            self._send(status, {"error": exc.detail, "kind": exc.kind.value,
                                "request_id": request_id})
            auth_service.audit(
                request_id=request_id, actor_kind=actor_kind, actor_id=actor_id,
                action=f"{method} {path}", resource=path,
                outcome=AuditOutcome.ERROR, detail={"kind": exc.kind.value},
            )
        except Exception as exc:
            self._send(500, {"error": "internal_error",
                             "request_id": request_id})
            auth_service.audit(
                request_id=request_id, actor_kind=actor_kind, actor_id=actor_id,
                action=f"{method} {path}", resource=path, outcome=AuditOutcome.ERROR,
                detail={"type": type(exc).__name__},
            )

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_DELETE(self) -> None:
        self._dispatch("DELETE")

    def do_PATCH(self) -> None:
        self._dispatch("PATCH")

    def _actor(self) -> ConsoleUser:
        """取当前请求的控制台用户。

        权限表已经保证这些路由非认证不可达；这里再兜一层，避免路由与权限表
        将来不一致时把 None 传给服务层变成 500。
        """
        if self._user is None:
            raise AuthError("unauthenticated", "该操作需要控制台会话。")
        return self._user

    # ---------- 路由 ----------

    def _route_get(self, parsed) -> None:
        path = parsed.path
        if path == "/api/health":
            self._send(200, {"ok": True, "scan_root": str(SCAN_ROOT), "bind": BIND_HOST})
        elif path == "/api/engines":
            self._send(200, {"engines": _engine_rows()})
        elif path == "/api/providers":
            self._send(200, provider_catalog(probe_service.probe_status_map()))
        elif path == "/api/v1/products":
            # 能力矩阵原样回传：verification 与 unsupported_reason 由界面
            # 直接展示，控制面不做"看起来支持"的加工。
            self._send(200, {"products": [descriptor.model_dump()
                                          for descriptor in product_catalog.descriptors()]})
        elif path == "/api/summary":
            self._send(200, scan_service.runs.summary())
        elif path == "/api/scans":
            query = parse_qs(parsed.query)
            limit = min(max(int((query.get("limit") or [50])[0]), 1), 200)
            rows = scan_service.runs.list(limit=limit)
            self._send(200, {"scans": [_legacy_run(row) for row in rows]})
        elif path.startswith("/api/scans/") and path.endswith("/raw-report"):
            run_id = urllib.parse.unquote(path[len("/api/scans/"):-len("/raw-report")])
            raw = scan_service.runs.raw_report_for_run(run_id)
            if not raw:
                self._send(404, {"error": "找不到该扫描的原始报告。"})
                return
            # content 落库时是 JSON 字符串，能解析就还原成对象，否则原样回传。
            try:
                content = json.loads(raw["content"])
            except (ValueError, TypeError):
                content = raw["content"]
            self._send(200, {
                "detector_run_id": run_id,
                "uri": raw["uri"],
                "media_type": raw["media_type"],
                "sha256": raw["sha256"],
                "byte_length": raw["byte_length"],
                "created_at": raw["created_at"],
                "content": content,
            })
        elif path.startswith("/api/scans/"):
            run_id = urllib.parse.unquote(path.rsplit("/", 1)[-1])
            row = scan_service.runs.get(run_id)
            if not row:
                self._send(404, {"error": "找不到该扫描记录。"})
                return
            findings = scan_service.runs.findings_for_run(run_id)
            self._send(200, {"scan": _legacy_run(row),
                             "findings": [_legacy_finding(item) for item in findings]})
        elif path == "/api/session":
            # 当前会话信息；同时是前端判断会话是否仍有效的探针。
            actor = self._actor()
            self._send(200, {"username": actor.username, "role": actor.role.value,
                             "user_id": actor.user_id})
        elif path == "/api/users":
            self._send(200, {"users": auth_service.list_users(actor=self._actor())})
        elif path == "/api/devices":
            self._send(200, {"devices": auth_service.list_devices(actor=self._actor())})
        elif path == "/api/audit":
            query = parse_qs(parsed.query)
            limit = min(max(int((query.get("limit") or [100])[0]), 1), 500)
            self._send(200, {"events": auth_service.audit_events(
                actor=self._actor(), limit=limit,
                actor_kind=(query.get("actor_kind") or [None])[0],
                action=(query.get("action") or [None])[0],
                since=(query.get("since") or [None])[0],
            )})
        elif path.startswith("/api/retention"):
            self._send(200, {"rules": auth_service.retention_rules()})
        elif parsed.path == "/" or parsed.path.startswith("/web/"):
            relative = "index.html" if parsed.path == "/" else parsed.path.removeprefix("/web/")
            file_path = (WEB_ROOT / relative).resolve()
            if WEB_ROOT not in file_path.parents and file_path != WEB_ROOT / "index.html":
                self._send(404, "未找到页面。", "text/plain; charset=utf-8")
                return
            if not file_path.is_file():
                self._send(404, "未找到页面。", "text/plain; charset=utf-8")
                return
            mime = "text/html; charset=utf-8" if file_path.suffix == ".html" else "text/css; charset=utf-8" if file_path.suffix == ".css" else "text/javascript; charset=utf-8"
            self._send(200, file_path.read_bytes(), mime)
        else:
            self._send(404, {"error": "找不到该接口。"})

    def _route_post(self, parsed) -> None:
        path = parsed.path
        if path == "/api/session":
            body = self._body()
            result = auth_service.login(
                username=str(body.get("username") or ""),
                password=str(body.get("password") or ""),
            )
            self._send(200, result, extra_headers={
                "Set-Cookie": self._session_cookie(result["token"],
                                                    max_age=result["expires_in_seconds"])
            })
            return

        if _is_probe_path(path):
            provider_id = _probe_provider_id(path)
            if provider_id not in KNOWN_PROVIDERS:
                self._send(404, {"error": "找不到该供应商。"})
                return
            # 两条 profile 分别 Probe：通过 Codex 的 Responses 不代表
            # 扫描器的 Chat Completions 可用，反之亦然。
            results = [
                probe_service.probe(provider_id=provider_id, profile_kind=kind)
                for kind in PROFILE_KINDS
            ]
            self._send(200, {"provider_id": provider_id, "results": results})
            return

        body = self._body()
        if path == "/api/scans":
            target = _safe_target(body.get("target"))
            target_ref = target.relative_to(SCAN_ROOT).as_posix()
            result = scan_service.scan(
                detector_id=str(body.get("engine") or ""),
                target=target,
                target_ref=target_ref,
                timeout_seconds=SCAN_TIMEOUT_SECONDS,
                idempotency_key=body.get("idempotency_key"),
            )
            self._send(201, result)
        elif path == "/api/scans/import":
            report = body.get("report")
            if not isinstance(report, (dict, list)):
                raise ValueError("报告内容必须是 SARIF 或扫描器 JSON 对象。")
            if isinstance(report, list):
                report = {"findings": report}
            result = scan_service.import_report(
                detector_id=str(body.get("engine") or "imported-report")[:100],
                target_ref=str(body.get("target") or "imported report")[:1000],
                report=report,
                idempotency_key=body.get("idempotency_key"),
            )
            self._send(201, result)
        elif path == "/api/users":
            username = str(body.get("username") or "").strip()
            if not username:
                raise ValueError("用户名不能为空。")
            password = str(body.get("password") or "")
            if len(password) < 12:
                raise ValueError("密码至少 12 位。")
            role = ConsoleRole(str(body.get("role") or "viewer"))
            user_id = auth_service.create_user(actor=self._actor(), username=username,
                                               password=password, role=role)
            self._send(201, {"user_id": user_id})
        elif path.startswith("/api/users/") and path.endswith("/password"):
            user_id = urllib.parse.unquote(path[len("/api/users/"):-len("/password")])
            auth_service.change_password(
                user_id=user_id,
                old_password=str(body.get("old_password") or ""),
                new_password=str(body.get("new_password") or ""),
            )
            self._send(200, {"ok": True, "user_id": user_id})
        elif path == "/api/devices":
            label = str(body.get("label") or "").strip()
            if not label:
                raise ValueError("设备标签不能为空。")
            self._send(201, auth_service.enroll_device(actor=self._actor(), label=label))
        elif path.startswith("/api/devices/") and path.endswith("/rotate-token"):
            device_id = path.split("/")[3]
            auth_service.require(self._actor(), Permission.MANAGE_USERS)
            token = ingestion_service.devices.rotate_credential(device_id=device_id)
            self._send(200, {"device_id": device_id, "token": token})
        elif path == "/api/retention":
            data_kind = RetentionKind(str(body.get("data_kind") or ""))
            days = int(body.get("retention_days"))
            if days < 1:
                raise ValueError("保留天数至少 1 天。")
            auth_service.set_retention_rule(actor=self._actor(), data_kind=data_kind,
                                            retention_days=days,
                                            enabled=bool(body.get("enabled", True)))
            self._send(200, {"ok": True, "data_kind": data_kind.value})
        elif path == "/api/retention/prune":
            self._send(200, auth_service.run_retention(actor=self._actor()))
        else:
            self._send(404, {"error": "找不到该接口。"})

    def _route_delete(self, parsed) -> None:
        if parsed.path == "/api/session":
            # 吊销当前会话；浏览器端由 HttpOnly Cookie 带上令牌。
            if self._session_row is not None:
                auth_service.logout(session_id=self._session_row["session_id"])
            self._send(200, {"ok": True})
        else:
            self._send(404, {"error": "找不到该接口。"})

    def _route_patch(self, parsed) -> None:
        path = parsed.path
        body = self._body()
        actor = self._actor()
        if path.startswith("/api/users/") and path.count("/") == 3:
            user_id = urllib.parse.unquote(path.rsplit("/", 1)[-1])
            changed = False
            if "role" in body:
                auth_service.set_role(actor=actor, user_id=user_id,
                                      role=ConsoleRole(str(body["role"])))
                changed = True
            if "disabled" in body:
                auth_service.set_disabled(actor=actor, user_id=user_id,
                                          disabled=bool(body["disabled"]))
                changed = True
            if not changed:
                raise ValueError("需要提供 role 或 disabled 字段。")
            self._send(200, {"ok": True, "user_id": user_id})
        elif path.startswith("/api/devices/") and path.count("/") == 3:
            device_id = urllib.parse.unquote(path.rsplit("/", 1)[-1])
            if "host_id" in body:
                host_id = body["host_id"]
                if not isinstance(host_id, str) or not host_id.strip() or len(host_id) > 160:
                    raise ValueError("invalid_host_id")
                ingestion_service.devices.set_host(device_id=device_id, host_id=host_id)
            if "status" in body:
                status = DeviceStatus(str(body["status"]))
                auth_service.set_device_status(actor=actor, device_id=device_id, status=status)
            if not {"host_id", "status"}.intersection(body):
                raise ValueError("host_id_or_status_required")
            self._send(200, {"ok": True, "device_id": device_id})
        else:
            self._send(404, {"error": "找不到该接口。"})


PROBE_PREFIX = "/api/providers/"
PROBE_SUFFIX = "/probe"


def _is_probe_path(path: str) -> bool:
    return path.startswith(PROBE_PREFIX) and path.endswith(PROBE_SUFFIX)


def _probe_provider_id(path: str) -> str:
    return path[len(PROBE_PREFIX):-len(PROBE_SUFFIX)]


def main() -> None:
    SCAN_ROOT.mkdir(parents=True, exist_ok=True)
    # 首次启动建立管理员。口令优先取 FUSION_ADMIN_PASSWORD，否则生成一次性
    # 随机口令并只打印这一次——不使用任何默认口令。
    bootstrapped = auth_service.bootstrap_admin(
        password=os.environ.get("FUSION_ADMIN_PASSWORD") or None
    )
    if bootstrapped:
        print(f"已创建管理员账号：{bootstrapped[0]}")
        if not os.environ.get("FUSION_ADMIN_PASSWORD"):
            print(f"一次性口令：{bootstrapped[1]}")
    purged = auth_service.purge_expired_sessions()
    if purged:
        print(f"已清理过期会话 {purged} 条。")
    server = ThreadingHTTPServer((BIND_HOST, int(os.environ.get("PORT", "8000"))), Handler)
    display_host = "127.0.0.1" if BIND_HOST in {"0.0.0.0", "::"} else BIND_HOST
    print(f"ASGP 已启动：http://{display_host}:{server.server_port}（监听 {BIND_HOST}）")
    print(f"扫描目录：{SCAN_ROOT}")
    print(f"数据库：{DB_PATH}")
    server.serve_forever()


if __name__ == "__main__":
    main()
