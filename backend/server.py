"""ASGP 控制面 HTTP 服务（扫描集成原型）。

本文件只做协议适配：目标校验、响应形状和静态页面。检测器执行、归一化与
持久化在 adapters/detectors、services/scan_service 和 storage/ 中完成。

当前端点未版本化且无认证，仅用于本轮查看原型；对外提供服务前必须实现
控制台认证、设备认证和审计（见 IMPLEMENTATION_PLAN.md P0 验收）。
"""

from __future__ import annotations

import json
import os
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from adapters.detectors import DetectorError
from detectors.registry import DetectorCatalog
from model_providers import PROFILE_KINDS, provider_catalog
from services.provider_probe import ProviderProbeService
from services.scan_service import ScanService
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
catalog = DetectorCatalog(
    data_root=DATA_ROOT,
    timeout_seconds=SCAN_TIMEOUT_SECONDS,
    probe_status=probe_service.status_for,
)
scan_service = ScanService(storage=storage, catalog=catalog)


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
    server_version = "ASGP/0.2"

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[{now_iso()}] {fmt % args}")

    def _send(self, status: int, payload: Any, content_type: str = "application/json; charset=utf-8") -> None:
        body = payload if isinstance(payload, bytes) else json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _body(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0 or length > MAX_BODY_BYTES:
            raise ValueError(f"请求内容大小须在 1 到 {MAX_BODY_BYTES} 字节之间。")
        raw = self.rfile.read(length)
        value = json.loads(raw.decode("utf-8"))
        if not isinstance(value, dict):
            raise ValueError("请求内容必须是 JSON 对象。")
        return value

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/health":
            self._send(200, {"ok": True, "scan_root": str(SCAN_ROOT), "bind": BIND_HOST})
        elif parsed.path == "/api/engines":
            self._send(200, {"engines": _engine_rows()})
        elif parsed.path == "/api/providers":
            self._send(200, provider_catalog(probe_service.probe_status_map()))
        elif parsed.path == "/api/summary":
            self._send(200, scan_service.runs.summary())
        elif parsed.path == "/api/scans":
            query = parse_qs(parsed.query)
            limit = min(max(int((query.get("limit") or [50])[0]), 1), 200)
            rows = scan_service.runs.list(limit=limit)
            self._send(200, {"scans": [_legacy_run(row) for row in rows]})
        elif parsed.path.startswith("/api/scans/"):
            run_id = urllib.parse.unquote(parsed.path.rsplit("/", 1)[-1])
            row = scan_service.runs.get(run_id)
            if not row:
                self._send(404, {"error": "找不到该扫描记录。"})
                return
            findings = scan_service.runs.findings_for_run(run_id)
            self._send(200, {"scan": _legacy_run(row),
                             "findings": [_legacy_finding(item) for item in findings]})
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

    def do_POST(self) -> None:
        try:
            if _is_probe_path(self.path):
                provider_id = _probe_provider_id(self.path)
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
            if self.path == "/api/scans":
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
            elif self.path == "/api/scans/import":
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
            else:
                self._send(404, {"error": "找不到该接口。"})
        except ValueError as exc:
            self._send(400, {"error": str(exc)})
        except KeyError as exc:
            self._send(400, {"error": f"未知的扫描引擎：{exc.args[0]}"})
        except DetectorError as exc:
            # 目标形态/凭据问题是请求问题；超时、退出码、解析失败是执行问题。
            client_side = exc.kind.value in ("invalid_target", "missing_credential", "not_installed")
            self._send(400 if client_side else 409,
                       {"error": exc.detail, "kind": exc.kind.value})
        except RuntimeError as exc:
            self._send(409, {"error": str(exc)})
        except Exception as exc:
            self._send(500, {"error": f"服务器内部错误（{type(exc).__name__}）：{exc}"})


def _now() -> str:
    return now_iso()


PROBE_PREFIX = "/api/providers/"
PROBE_SUFFIX = "/probe"


def _is_probe_path(path: str) -> bool:
    return path.startswith(PROBE_PREFIX) and path.endswith(PROBE_SUFFIX)


def _probe_provider_id(path: str) -> str:
    return path[len(PROBE_PREFIX):-len(PROBE_SUFFIX)]


def main() -> None:
    SCAN_ROOT.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer((BIND_HOST, int(os.environ.get("PORT", "8000"))), Handler)
    display_host = "127.0.0.1" if BIND_HOST in {"0.0.0.0", "::"} else BIND_HOST
    print(f"ASGP 已启动：http://{display_host}:{server.server_port}（监听 {BIND_HOST}）")
    print(f"扫描目录：{SCAN_ROOT}")
    print(f"数据库：{DB_PATH}")
    server.serve_forever()


if __name__ == "__main__":
    main()
