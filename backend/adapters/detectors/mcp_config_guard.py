"""本地 MCP 配置静态守卫：补齐纯 mcpServers 配置（含 SKILL.md 内嵌）中管道执行与未固定包漏洞。"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Callable

from adapters.detectors.base import (
    DetectorAdapter,
    HealthReport,
    NormalizedFinding,
    RawOutput,
    ScanRequest,
)
from adapters.detectors.errors import DetectorError, ErrorKind
from adapters.detectors.normalize import normalize_report
from domain import DetectorDescriptor, DetectorMode

GUARD_VERSION = "0.1.0"

_FENCED_JSON_RE = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL | re.IGNORECASE)
_SHELL_BINS = frozenset({"sh", "bash", "zsh", "dash", "ash", "ksh", "cmd", "cmd.exe", "powershell", "pwsh"})
_PIPE_EXEC_RE = re.compile(
    r"(?:curl|wget|fetch|iwr|irm)\b[^\n]*\|\s*(?:sh|bash|zsh|dash|python\d*|perl|ruby|node|pwsh|powershell)\b"
    r"|(?:sh|bash|zsh)\s+-c\s+[\x22\x27]?[^\n]*\|\s*(?:sh|bash|python\d*)"
    r"|\|\s*(?:sh|bash|zsh|dash|pwsh|powershell)\b",
    re.IGNORECASE,
)
_SHELL_META_RE = re.compile(r"(?:&&|\|\||;|\$\(|`|\|)")
_RUNNER_BINS = frozenset({"npx", "pnpx", "bunx", "uvx", "pipx"})
_PINNED_NPM_RE = re.compile(r"^(?:@[^/]+/)?[A-Za-z0-9._-]+@\d+\.\d+\.\d+(?:[-+][A-Za-z0-9._-]+)?$")
_PINNED_PY_RE = re.compile(r"^[A-Za-z0-9._-]+==\d+\.\d+(?:\.\d+)?$")
_SECRET_VAL_RE = re.compile(r"(?:sk-[A-Za-z0-9_-]{12,}|ghp_[A-Za-z0-9]{16,}|AKIA[0-9A-Z]{16}|Bearer\s+[A-Za-z0-9._-]{12,})")
_SENSITIVE_PATHS = (".ssh/id_rsa", ".ssh/id_ed25519", ".aws/credentials", ".kube/config", ".git-credentials", "/etc/shadow", "/etc/gshadow")


def _iter_mcp_blocks(target: Path) -> list[tuple[str, dict[str, Any]]]:
    """从单个 JSON / Markdown 文件或目录提取全部 (相对位置, mcpServers 字典)。"""
    files: list[Path] = []
    if target.is_file():
        files = [target]
    elif target.is_dir():
        for p in sorted(target.rglob("*")):
            if p.is_symlink() or not p.is_file():
                continue
            if p.suffix.lower() in {".json", ".md"}:
                files.append(p)
    blocks: list[tuple[str, dict[str, Any]]] = []
    for path in files:
        rel = path.name if target.is_file() else path.relative_to(target).as_posix()
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if path.suffix.lower() == ".json":
            try:
                parsed = json.loads(text)
            except ValueError:
                continue
            if isinstance(parsed, dict) and isinstance(parsed.get("mcpServers"), dict):
                blocks.append((rel, parsed["mcpServers"]))
        elif path.suffix.lower() == ".md":
            for idx, match in enumerate(_FENCED_JSON_RE.finditer(text), 1):
                try:
                    parsed = json.loads(match.group(1))
                except ValueError:
                    continue
                if isinstance(parsed, dict) and isinstance(parsed.get("mcpServers"), dict):
                    blocks.append((f"{rel}#block-{idx}", parsed["mcpServers"]))
    return blocks


def _is_unpinned_runner(cmd_name: str, args: list[str]) -> str | None:
    if cmd_name not in _RUNNER_BINS:
        return None
    pkg_candidates = [a for a in args if isinstance(a, str) and a and not a.startswith("-")]
    if not pkg_candidates:
        return None
    pkg = pkg_candidates[0]
    if pkg.endswith("@latest") or "@latest" in pkg:
        return pkg
    if cmd_name in {"npx", "pnpx", "bunx"} and not _PINNED_NPM_RE.match(pkg):
        return pkg
    if cmd_name in {"uvx", "pipx"} and not _PINNED_PY_RE.match(pkg):
        return pkg
    return None


def analyze_mcp_configs(target: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for loc, servers in _iter_mcp_blocks(target):
        for name, cfg in sorted(servers.items()):
            if not isinstance(cfg, dict):
                continue
            raw_cmd = str(cfg.get("command") or "").strip()
            cmd_base = Path(raw_cmd).name.lower() if raw_cmd else ""
            raw_args = cfg.get("args") if isinstance(cfg.get("args"), list) else []
            args = [str(a) for a in raw_args]
            combined = " ".join([raw_cmd, *args]).strip()

            if _PIPE_EXEC_RE.search(combined):
                findings.append({
                    "rule_id": "MCG_SHELL_PIPE_EXEC",
                    "title": f"MCP server '{name}' executes remote script via shell pipeline",
                    "severity": "critical",
                    "confidence": "high",
                    "message": f"mcpServers.{name} ({loc}) contains download/pipe-to-shell command: {combined[:180]}",
                    "file": loc,
                })
            elif cmd_base in _SHELL_BINS and _SHELL_META_RE.search(combined):
                findings.append({
                    "rule_id": "MCG_SHELL_WRAPPER",
                    "title": f"MCP server '{name}' wraps launch inside shell metacharacters",
                    "severity": "high",
                    "confidence": "high",
                    "message": f"mcpServers.{name} ({loc}) uses shell wrapper '{cmd_base}' with compound operators.",
                    "file": loc,
                })

            unpinned = _is_unpinned_runner(cmd_base, args)
            if not unpinned and cmd_base in _SHELL_BINS:
                # 同步检测 sh -c "npx foo ..." 里的未固定包名。
                for tok_runner in _RUNNER_BINS:
                    m = re.search(rf"\b{tok_runner}\s+(?:-y\s+|--yes\s+)?([^\s;&|]+)", combined)
                    if m:
                        candidate = m.group(1)
                        if _is_unpinned_runner(tok_runner, [candidate]):
                            unpinned = candidate
                            break
            if unpinned:
                findings.append({
                    "rule_id": "MCG_UNPINNED_PACKAGE",
                    "title": f"MCP server '{name}' uses unpinned runtime package '{unpinned}'",
                    "severity": "medium",
                    "confidence": "high",
                    "message": f"mcpServers.{name} ({loc}) launches unpinned package '{unpinned}' without exact version.",
                    "file": loc,
                })

            env_map = cfg.get("env") if isinstance(cfg.get("env"), dict) else {}
            secret_hit = any(_SECRET_VAL_RE.search(str(v)) for v in env_map.values())
            sens_hit = any(sp in combined.lower() for sp in _SENSITIVE_PATHS)
            if secret_hit or sens_hit:
                findings.append({
                    "rule_id": "MCG_SENSITIVE_OR_SECRET",
                    "title": f"MCP server '{name}' embeds hardcoded credential or sensitive path",
                    "severity": "high",
                    "confidence": "high",
                    "message": f"mcpServers.{name} ({loc}) exposes hardcoded secret in env or references sensitive credential path.",
                    "file": loc,
                })
    return findings


class McpConfigGuardAdapter(DetectorAdapter):
    """纯本地 MCP 启动配置静态守卫，补足外部扫描器对 mcpServers.args 的覆盖空白。"""

    def __init__(
        self,
        *,
        data_root: Path,
        timeout_seconds: int = 300,
        max_output_bytes: int = 8 * 1024 * 1024,
        probe_status: Callable[[str, str], str] | None = None,
    ) -> None:
        self._data_root = Path(data_root)
        self._timeout_seconds = timeout_seconds
        self._max_output_bytes = max_output_bytes
        self._probe_status = probe_status

    @property
    def detector_id(self) -> str:
        return "mcp-config-guard"

    @property
    def engine_version(self) -> str:
        return GUARD_VERSION

    def descriptor(self) -> DetectorDescriptor:
        return DetectorDescriptor(
            detector_id=self.detector_id,
            version=self.engine_version,
            upstream_source="asgp/builtin-mcp-config-guard",
            license_id="Apache-2.0",
            input_types=["mcp_config_json", "skill_directory", "skill_md"],
            mode=DetectorMode.STATIC,
            llm_required=False,
            capabilities=["json"],
            boundary="纯本地静态规则检查 mcpServers 启动配置及 Markdown 内嵌配置，不执行或连接 MCP",
        )

    def health_check(self) -> HealthReport:
        return HealthReport(installed=True, runnable=True, version=self.engine_version)

    def validate_target(self, target: Path) -> Path:
        if not target.exists():
            raise DetectorError(ErrorKind.INVALID_TARGET, "MCP Config Guard 目标路径不存在。")
        if target.is_file() and target.suffix.lower() not in {".json", ".md"}:
            raise DetectorError(ErrorKind.INVALID_TARGET, "MCP Config Guard 只接受 .json / .md 文件或包含它们的目录。")
        return target

    def build_argv(self, target: Path, output_path: Path | None) -> list[str]:
        return []

    def scan(self, request: ScanRequest) -> RawOutput:
        target = self.validate_target(request.target)
        report = {"detector": self.detector_id, "version": self.engine_version, "findings": analyze_mcp_configs(target)}
        raw_bytes = json.dumps(report, ensure_ascii=False, sort_keys=True).encode("utf-8")
        if len(raw_bytes) > min(self._max_output_bytes, request.max_output_bytes):
            raise DetectorError(ErrorKind.OUTPUT_LIMIT_EXCEEDED, "MCP Config Guard 输出超过上限。")
        return RawOutput(
            report=report,
            media_type="application/json",
            sha256=hashlib.sha256(raw_bytes).hexdigest(),
            byte_length=len(raw_bytes),
        )

    def normalize(self, raw: RawOutput) -> list[NormalizedFinding]:
        return normalize_report(raw.report)
