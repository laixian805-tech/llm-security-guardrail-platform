from __future__ import annotations

import json
import os
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import uuid
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from model_providers import provider_catalog, scanner_provider_environment

ROOT = Path(__file__).resolve().parents[1]
WEB_ROOT = ROOT / "web"
DATA_ROOT = ROOT / "data"
SCAN_ROOT = Path(os.environ.get("FUSION_SCAN_ROOT", str(ROOT / "workspace"))).resolve()
DB_PATH = Path(os.environ.get("FUSION_DB_PATH", str(DATA_ROOT / "fusion.db")))
BIND_HOST = os.environ.get("FUSION_BIND", "127.0.0.1")
MAX_BODY_BYTES = 8 * 1024 * 1024
SCAN_TIMEOUT_SECONDS = 300
_DB_LOCK = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def _init_db() -> None:
    DATA_ROOT.mkdir(parents=True, exist_ok=True)
    SCAN_ROOT.mkdir(parents=True, exist_ok=True)
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _connect() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                engine TEXT NOT NULL,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL,
                finding_count INTEGER NOT NULL,
                summary TEXT NOT NULL,
                raw_report TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS findings (
                finding_id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
                engine TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                file TEXT NOT NULL,
                line INTEGER NOT NULL,
                risk_score REAL,
                metadata TEXT NOT NULL DEFAULT '{}',
                fingerprint TEXT NOT NULL,
                imported_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS findings_scan_id ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS findings_severity ON findings(severity);
            """
        )
        finding_columns = {row["name"] for row in conn.execute("PRAGMA table_info(findings)")}
        if "risk_score" not in finding_columns:
            conn.execute("ALTER TABLE findings ADD COLUMN risk_score REAL")
        if "metadata" not in finding_columns:
            conn.execute("ALTER TABLE findings ADD COLUMN metadata TEXT NOT NULL DEFAULT '{}'")


def _engine_rows() -> list[dict[str, Any]]:
    commands = {
        "skillspector": ("skillspector", "NVIDIA/SkillSpector", "Apache-2.0",
                         "Skill 静态扫描", "静态扫描；关闭 LLM 分析；OSV 查询可能访问网络"),
        "snyk-agent-scan": ("snyk-agent-scan", "snyk/agent-scan", "Apache-2.0",
                            "Agent 与 Skill 扫描", "仅允许扫描 Skill；需 SNYK_TOKEN；CLI 输出格式仍可能变化"),
        "mcp-scanner": ("mcp-scanner", "cisco-ai-defense/mcp-scanner", "Apache-2.0",
                        "MCP 工具定义扫描", "仅扫描静态工具清单 JSON；不连接或启动 MCP 服务"),
        "aig-skill-scan": ("aig-skill-scan", "Tencent/AI-Infra-Guard", "Apache-2.0 + NOTICE",
                           "LLM 辅助 Skill 审计", "调用配置的 LLM 服务，目标内容会发送给该服务"),
        "aig-mcp-scan": ("aig-mcp-scan", "Tencent/AI-Infra-Guard", "Apache-2.0 + NOTICE",
                         "LLM 辅助 MCP 源码审计", "调用配置的 LLM 服务，目标内容会发送给该服务"),
        "aig-agent-scan": ("aig-agent-scan", "Tencent/AI-Infra-Guard", "Apache-2.0 + NOTICE",
                           "Agent 动态评估", "需要明确配置运行中的目标；当前界面不直接运行"),
    }
    catalog = provider_catalog()
    selected_profile = next((p for p in catalog["providers"] if p["id"] == catalog["selected"]), None)
    selected_provider_ready = bool(selected_profile and selected_profile["scanner_profile"]["configured"])
    rows = []
    for key, (binary, source, license_name, purpose, boundary) in commands.items():
        override = os.environ.get(f"FUSION_BIN_{key.upper().replace('-', '_')}")
        path = (override if override and Path(override).is_file() and os.access(override, os.X_OK)
                else shutil.which(binary))
        gated = (key == "snyk-agent-scan" and not os.environ.get("SNYK_TOKEN")) or (
            key in {"aig-skill-scan", "aig-mcp-scan"} and not selected_provider_ready
        ) or key == "aig-agent-scan"
        rows.append({
            "id": key,
            "binary": binary,
            "source": source,
            "license": license_name,
            "purpose": purpose,
            "boundary": boundary,
            "available": bool(path),
            "runnable": bool(path) and not gated,
            "executable": path or "",
        })
    rows.extend([
        {"id": "toolhive", "binary": "thv", "source": "stacklok/toolhive",
         "license": "Apache-2.0", "purpose": "MCP 运行时注册与网关",
         "boundary": "运行时组件，不是扫描器", "available": bool(shutil.which("thv")),
         "runnable": False, "executable": shutil.which("thv") or ""},
        {"id": "llm-guard", "binary": "", "source": "protectai/llm-guard",
         "license": "MIT", "purpose": "模型输入/输出扫描器",
         "boundary": "上游已归档，仅作参考", "available": False, "runnable": False,
         "executable": ""},
    ])
    return rows


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


def _severity(value: Any) -> str:
    normalized = str(value or "unknown").strip().lower()
    if normalized in {"critical", "error", "fatal", "blocker"}:
        return "critical"
    if normalized in {"high", "warning", "major"}:
        return "high"
    if normalized in {"medium", "moderate"}:
        return "medium"
    if normalized in {"low", "note", "minor"}:
        return "low"
    if normalized in {"info", "informational"}:
        return "info"
    return "unknown"


def _sarif_findings(engine: str, report: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for run in report.get("runs", []) if isinstance(report.get("runs"), list) else []:
        driver = ((run.get("tool") or {}).get("driver") or {})
        rules = {str(item.get("id")): item for item in driver.get("rules", [])
                 if isinstance(item, dict) and item.get("id")}
        run_engine = str(driver.get("name") or engine)
        results = run.get("results", []) if isinstance(run.get("results"), list) else []
        for result in results:
            if not isinstance(result, dict):
                continue
            rule_id = str(result.get("ruleId") or "unknown")
            rule = rules.get(rule_id, {})
            message = result.get("message") or {}
            text = str(message.get("text") or message.get("markdown") or rule_id)
            locations = result.get("locations") or []
            physical = (((locations[0] or {}).get("physicalLocation") or {})
                        if locations else {})
            artifact = physical.get("artifactLocation") or {}
            region = physical.get("region") or {}
            title_value = rule.get("shortDescription") or {}
            properties = result.get("properties") or {}
            rule_properties = rule.get("properties") or {}
            raw_score = (properties.get("security-severity") or properties.get("risk_score") or
                         rule_properties.get("security-severity"))
            try:
                score = float(raw_score) if raw_score is not None else None
            except (TypeError, ValueError):
                score = None
            findings.append({
                "engine": run_engine,
                "rule_id": rule_id,
                "title": str(title_value.get("text") or rule.get("name") or rule_id),
                "severity": _severity(result.get("level") or rule.get("defaultConfiguration", {}).get("level")),
                "message": text,
                "file": str(artifact.get("uri") or ""),
                "line": int(region.get("startLine") or 0),
                "risk_score": score,
                "metadata": properties,
                "fingerprint": str((result.get("partialFingerprints") or {}).get("primaryLocationLineHash") or ""),
            })
    return findings


def _json_findings(engine: str, report: Any) -> list[dict[str, Any]]:
    if not isinstance(report, dict):
        if isinstance(report, list):
            report = {"findings": report}
        else:
            return []
    if isinstance(report.get("scan_path_responses"), list):
        return _snyk_findings(engine, report)
    rows: list[Any] = []
    for key in ("findings", "issues", "vulnerabilities", "alerts", "results", "risks", "scan_results"):
        value = report.get(key)
        if isinstance(value, list):
            rows.extend(value)
    findings = []
    for item in rows:
        if not isinstance(item, dict):
            continue
        analyzer_findings = item.get("findings")
        if isinstance(analyzer_findings, dict):
            entity_name = str(item.get("tool_name") or item.get("prompt_name") or
                              item.get("resource_name") or item.get("server_name") or "")
            for analyzer, details in analyzer_findings.items():
                if not isinstance(details, dict) or not int(details.get("total_findings") or 0):
                    continue
                names = details.get("threat_names") or []
                message = str(details.get("threat_summary") or ", ".join(map(str, names)))
                findings.append({
                    "engine": engine,
                    "rule_id": str(analyzer),
                    "title": str(details.get("threat_summary") or analyzer),
                    "severity": _severity(details.get("severity")),
                    "message": message,
                    "file": entity_name,
                    "line": 0,
                    "risk_score": None,
                    "metadata": {"analyzer": analyzer, "total_findings": details.get("total_findings"),
                                 "threat_names": names},
                    "fingerprint": "",
                })
            continue
        location = item.get("location") or item.get("locations") or {}
        if isinstance(location, list):
            location = location[0] if location else {}
        if not isinstance(location, dict):
            location = {}
        raw_score = item.get("risk_score", item.get("riskScore", item.get("score")))
        try:
            risk_score = float(raw_score) if raw_score is not None else None
        except (TypeError, ValueError):
            risk_score = None
        findings.append({
            "engine": engine,
            "rule_id": str(item.get("ruleId") or item.get("rule_id") or item.get("code") or item.get("id") or "unknown"),
            "title": str(item.get("title") or item.get("name") or item.get("risk") or item.get("rule") or "发现项"),
            "severity": _severity(item.get("severity") or item.get("level") or item.get("risk_level")),
            "message": str(item.get("message") or item.get("description") or item.get("detail") or ""),
            "file": str(item.get("file") or item.get("path") or location.get("file") or location.get("path") or ""),
            "line": int(item.get("line") or location.get("line") or 0),
            "risk_score": risk_score,
            "metadata": item.get("metadata") or item.get("details") or {},
            "fingerprint": str(item.get("fingerprint") or item.get("id") or ""),
        })
    return findings


def _snyk_findings(engine: str, report: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for path_result in report.get("scan_path_responses", []):
        if not isinstance(path_result, dict):
            continue
        path = str(path_result.get("path") or "")
        for entity_type, collection_key in (("skill", "skill_risks"), ("server", "server_risks")):
            for entity in path_result.get(collection_key, []) or []:
                if not isinstance(entity, dict):
                    continue
                indexes = entity.get("risk_indexes") or {}
                for risk_id, value in indexes.items():
                    if not isinstance(value, dict):
                        continue
                    score = value.get("score")
                    evidence = str(value.get("evidence") or "")
                    if score in (None, 0) and not evidence:
                        continue
                    locations = value.get("locations") or []
                    occurrence = (((locations[0] or {}).get("start") or {}) if locations else {})
                    try:
                        risk_score = float(score) if score is not None else None
                    except (TypeError, ValueError):
                        risk_score = None
                    findings.append({
                        "engine": engine,
                        "rule_id": str(risk_id),
                        "title": str(risk_id).replace("_", " ").title(),
                        "severity": "unknown",
                        "message": evidence,
                        "file": str(occurrence.get("path") or path),
                        "line": int(occurrence.get("line") or 0),
                        "risk_score": risk_score,
                        "metadata": {"entity_type": entity_type, "entity": entity.get("name", "")},
                        "fingerprint": "",
                    })
    return findings


def _normalize(engine: str, report: Any) -> list[dict[str, Any]]:
    if isinstance(report, dict) and report.get("version") == "2.1.0" and isinstance(report.get("runs"), list):
        return _sarif_findings(engine, report)
    return _json_findings(engine, report)


def _persist_scan(engine: str, target: str, report: Any, findings: list[dict[str, Any]],
                  started_at: str, status: str = "completed") -> dict[str, Any]:
    scan_id = str(uuid.uuid4())
    finished_at = _now()
    summary = {"finding_count": len(findings), "by_severity": {}}
    for finding in findings:
        severity = finding["severity"]
        summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1
    raw = json.dumps(report, ensure_ascii=False)
    with _DB_LOCK, _connect() as conn:
        conn.execute(
            "INSERT INTO scans VALUES (?,?,?,?,?,?,?,?,?)",
            (scan_id, engine, target, status, started_at, finished_at, len(findings),
             json.dumps(summary, ensure_ascii=False), raw),
        )
        for item in findings:
            conn.execute(
                "INSERT INTO findings (finding_id,scan_id,engine,rule_id,title,severity,message,file,line,"
                "risk_score,metadata,fingerprint,imported_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (str(uuid.uuid4()), scan_id, item["engine"], item["rule_id"], item["title"],
                 item["severity"], item["message"], item["file"], item["line"],
                 item.get("risk_score"), json.dumps(item.get("metadata") or {}, ensure_ascii=False),
                 item["fingerprint"], finished_at),
            )
    return {"scan_id": scan_id, "engine": engine, "target": target,
            "status": status, "finding_count": len(findings), "summary": summary}


def _scanner_environment(engine: str) -> dict[str, str]:
    """Pass only the environment variables required by the selected scanner."""
    child_home = DATA_ROOT / "engine-home" / engine
    child_tmp = DATA_ROOT / "tmp"
    child_home.mkdir(parents=True, exist_ok=True)
    child_tmp.mkdir(parents=True, exist_ok=True)
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(child_home),
        "TMPDIR": str(child_tmp),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
                 "http_proxy", "https_proxy", "all_proxy", "no_proxy",
                 "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE"):
        value = os.environ.get(name)
        if value:
            env[name] = value
    if engine == "snyk-agent-scan" and os.environ.get("SNYK_TOKEN"):
        env["SNYK_TOKEN"] = os.environ["SNYK_TOKEN"]
    if engine in {"aig-skill-scan", "aig-mcp-scan"}:
        env.update(scanner_provider_environment())
    return env


def _run_cli_scan(engine: str, target: Path) -> tuple[Any, str]:
    commands: dict[str, list[str]] = {}
    binaries = {row["id"]: row["executable"] for row in _engine_rows()}
    binary = binaries.get(engine)
    if not binary:
        raise RuntimeError(f"扫描引擎 {engine} 尚未安装或配置。")
    target_rel = target.relative_to(SCAN_ROOT).as_posix()
    child_env = _scanner_environment(engine)
    if engine == "skillspector":
        with tempfile.NamedTemporaryFile(prefix="fusion-", suffix=".sarif", dir=DATA_ROOT,
                                         delete=False) as output:
            output_path = Path(output.name)
        output_path.unlink(missing_ok=True)
        commands[engine] = [binary, "scan", str(target), "--no-llm", "--format", "sarif",
                            "--output", str(output_path)]
    elif engine == "snyk-agent-scan":
        if not (target.is_file() and target.name.lower() == "skill.md" or
                target.is_dir() and (target / "SKILL.md").is_file()):
            raise ValueError("Snyk Agent Scan 仅允许扫描包含 SKILL.md 的目录或 SKILL.md 文件。")
        if not child_env.get("SNYK_TOKEN"):
            raise ValueError("运行 Snyk Agent Scan 前请设置 SNYK_TOKEN。")
        commands[engine] = [binary, str(target), "--json"]
        output_path = None
    elif engine == "mcp-scanner":
        if not target.is_file() or target.suffix.lower() != ".json":
            raise ValueError("Cisco MCP Scanner 适配器只接受静态工具清单 JSON 文件。")
        commands[engine] = [binary, "--log-level", "error", "--analyzers", "yara", "--format", "raw", "static",
                            "--tools", str(target)]
        output_path = None
    elif engine in {"aig-skill-scan", "aig-mcp-scan"}:
        if not child_env.get("LLM_API_KEY"):
            raise ValueError("运行此引擎前，请配置所选模型供应商的 API 凭据和 Chat Completions 接口。")
        scan_target = target
        if engine == "aig-skill-scan" and target.is_file():
            if target.name.lower() != "skill.md":
                raise ValueError("A.I.G Skill Scan 需要 Skill 目录或 SKILL.md 文件。")
            scan_target = target.parent
        if engine == "aig-mcp-scan" and not target.is_dir():
            raise ValueError("A.I.G MCP Scan 需要源码目录；在线 MCP URL 扫描未开放。")
        with tempfile.NamedTemporaryFile(prefix="fusion-", suffix=".sarif", dir=DATA_ROOT,
                                         delete=False) as output:
            output_path = Path(output.name)
        output_path.unlink(missing_ok=True)
        commands[engine] = [binary, "--repo", str(scan_target), "--language", "en", "-o", str(output_path)]
    else:
        raise ValueError(f"引擎 {engine} 不能通过当前扫描入口运行。")

    try:
        result = subprocess.run(commands[engine], capture_output=True, text=True,
                                timeout=SCAN_TIMEOUT_SECONDS, check=False,
                                cwd=str(SCAN_ROOT), env=child_env)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"扫描超时（{SCAN_TIMEOUT_SECONDS} 秒）。") from exc
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "扫描器未提供错误详情").strip()[-2000:]
        for secret_name in ("LLM_API_KEY", "SNYK_TOKEN", "STEPFUN_API_KEY", "XUNFEI_API_PASSWORD"):
            secret = child_env.get(secret_name, "")
            if secret:
                detail = detail.replace(secret, "[密钥已脱敏]")
        raise RuntimeError(f"{engine} 扫描器退出码为 {result.returncode}：{detail}")
    if output_path:
        try:
            report = json.loads(output_path.read_text(encoding="utf-8"))
        finally:
            output_path.unlink(missing_ok=True)
    else:
        try:
            report = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"{engine} 未返回可解析的 JSON：{result.stderr[-1200:]}") from exc
    return report, target_rel


class Handler(BaseHTTPRequestHandler):
    server_version = "ASGP/0.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[{_now()}] {fmt % args}")

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
            self._send(200, provider_catalog())
        elif parsed.path == "/api/summary":
            with _connect() as conn:
                scans = conn.execute("SELECT COUNT(*) AS n FROM scans").fetchone()["n"]
                findings = conn.execute("SELECT COUNT(*) AS n FROM findings").fetchone()["n"]
                severe = conn.execute("SELECT COUNT(*) AS n FROM findings WHERE severity IN ('critical','high')").fetchone()["n"]
                latest = conn.execute("SELECT finished_at FROM scans ORDER BY finished_at DESC LIMIT 1").fetchone()
            self._send(200, {"scans": scans, "findings": findings, "high_or_critical": severe,
                             "latest_scan": latest["finished_at"] if latest else ""})
        elif parsed.path == "/api/scans":
            query = parse_qs(parsed.query)
            limit = min(max(int((query.get("limit") or [50])[0]), 1), 200)
            with _connect() as conn:
                rows = conn.execute(
                    "SELECT scan_id,engine,target,status,started_at,finished_at,finding_count,summary "
                    "FROM scans ORDER BY finished_at DESC LIMIT ?", (limit,)
                ).fetchall()
            self._send(200, {"scans": [dict(row, summary=json.loads(row["summary"])) for row in rows]})
        elif parsed.path.startswith("/api/scans/"):
            scan_id = parsed.path.rsplit("/", 1)[-1]
            with _connect() as conn:
                scan = conn.execute(
                    "SELECT scan_id,engine,target,status,started_at,finished_at,finding_count,summary "
                    "FROM scans WHERE scan_id=?", (scan_id,)
                ).fetchone()
                if not scan:
                    self._send(404, {"error": "找不到该扫描记录。"})
                    return
                findings = conn.execute(
                    "SELECT finding_id,engine,rule_id,title,severity,message,file,line,risk_score,metadata,fingerprint "
                    "FROM findings WHERE scan_id=? ORDER BY CASE severity WHEN 'critical' THEN 0 "
                    "WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, file,line",
                    (scan_id,),
                ).fetchall()
            self._send(200, {"scan": dict(scan, summary=json.loads(scan["summary"])),
                             "findings": [dict(row) for row in findings]})
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
            body = self._body()
            if self.path == "/api/scans":
                engine = str(body.get("engine") or "")
                target = _safe_target(body.get("target"))
                started_at = _now()
                report, target_rel = _run_cli_scan(engine, target)
                findings = _normalize(engine, report)
                result = _persist_scan(engine, target_rel, report, findings, started_at)
                self._send(201, result)
            elif self.path == "/api/scans/import":
                engine = str(body.get("engine") or "imported-report")[:100]
                target = str(body.get("target") or "imported report")[:1000]
                report = body.get("report")
                if not isinstance(report, (dict, list)):
                    raise ValueError("报告内容必须是 SARIF 或扫描器 JSON 对象。")
                if isinstance(report, list):
                    report = {"findings": report}
                findings = _normalize(engine, report)
                if not findings:
                    raise ValueError("报告中没有找到可识别的 SARIF/JSON 发现项。")
                result = _persist_scan(engine, target, report, findings, _now(), status="imported")
                self._send(201, result)
            else:
                self._send(404, {"error": "找不到该接口。"})
        except (ValueError, json.JSONDecodeError) as exc:
            self._send(400, {"error": str(exc)})
        except RuntimeError as exc:
            self._send(409, {"error": str(exc)})
        except Exception as exc:
            self._send(500, {"error": f"服务器内部错误（{type(exc).__name__}）：{exc}"})


def main() -> None:
    _init_db()
    server = ThreadingHTTPServer((BIND_HOST, int(os.environ.get("PORT", "8000"))), Handler)
    display_host = "127.0.0.1" if BIND_HOST in {"0.0.0.0", "::"} else BIND_HOST
    print(f"ASGP 已启动：http://{display_host}:{server.server_port}（监听 {BIND_HOST}）")
    print(f"扫描目录：{SCAN_ROOT}")
    server.serve_forever()


if __name__ == "__main__":
    main()
