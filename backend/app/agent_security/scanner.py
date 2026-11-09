from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 edge hosts use the tomli backport.
    import tomli as tomllib  # type: ignore[no-redef]
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .adapters import module_from_command
from .asset_identity import (classify_carrier, derive_ids, infer_product,
                             normalized_content_hash, state_for_carrier)
from .assessment import scan_policy_verdict, score_findings
from .paths import agentsec_dir
from .models import (
    AssetCarrier,
    AssetKind,
    AssetState,
    ScanFinding,
    ScanReport,
    ScanVerdict,
    SecurityAction,
    Severity,
    utc_now_iso,
)
from .rules import DetectionRule, RULES_BY_ID, static_rules

REGISTRY_VERSION = 1
POPULAR_PACKAGES = (
    "requests", "numpy", "pandas", "flask", "django", "fastapi", "langchain",
    "openai", "pydantic", "pyyaml", "httpx", "urllib3", "cryptography", "boto3",
    "sqlalchemy", "celery", "scipy", "matplotlib", "tensorflow", "torch",
)

_CODE_BLOCK_RE = re.compile(r"```[a-zA-Z0-9_+-]*\n(.*?)```", re.DOTALL)
_INLINE_CODE_RE = re.compile(r"`([^`\n]{4,})`")
_BASE64_RUN_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
_HEX_RUN_RE = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
_CONCAT_RE = re.compile(r"""(["'])\s*\+\s*(["'])""")
_PATH_TRAVERSAL_RE = re.compile(r"(^|[\s\"'=])\.\.[\\/]")
_NETWORK_FETCH_RE = re.compile(r"(?i)(curl|wget|invoke-webrequest|iwr|nc\s)")


@dataclass
class Registry:
    """Local trusted-asset registry: name/kind/sha256/source/approver."""

    path: Path
    assets: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def load(cls, path: str | Path | None = None) -> "Registry":
        resolved = Path(path) if path else agentsec_dir() / "registry.json"
        if not resolved.exists():
            return cls(path=resolved)
        payload = json.loads(resolved.read_text(encoding="utf-8"))
        return cls(path=resolved, assets=list(payload.get("assets", [])))

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps({"version": REGISTRY_VERSION, "assets": self.assets},
                       ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def lookup(self, kind: str, name: str) -> dict[str, Any] | None:
        for asset in self.assets:
            if asset.get("kind") == kind and asset.get("name") == name:
                return asset
        return None

    def add(self, kind: str, name: str, sha256: str, *, source: str = "local",
            approved_by: str = "", note: str = "") -> dict[str, Any]:
        existing = self.lookup(kind, name)
        if existing is not None:
            existing.update({"sha256": sha256, "source": source,
                             "approved_by": approved_by, "note": note,
                             "approved_at": utc_now_iso()})
            asset = existing
        else:
            asset = {
                "kind": kind, "name": name, "sha256": sha256, "source": source,
                "approved_by": approved_by, "note": note, "approved_at": utc_now_iso(),
            }
            self.assets.append(asset)
        self.save()
        return asset

    def remove(self, kind: str, name: str) -> bool:
        before = len(self.assets)
        self.assets = [a for a in self.assets if not (a.get("kind") == kind and a.get("name") == name)]
        if len(self.assets) != before:
            self.save()
            return True
        return False


@dataclass(frozen=True)
class ScanTarget:
    kind: str            # skill | mcp | deps | hook
    name: str
    root: Path
    files: tuple[Path, ...]


def sha256_path(path: Path) -> str:
    """Stable digest of a file, or of a directory tree (sorted rel paths)."""
    digest = hashlib.sha256()
    if path.is_file():
        digest.update(path.read_bytes())
        return digest.hexdigest()
    for child in sorted(p for p in path.rglob("*") if p.is_file()):
        digest.update(str(child.relative_to(path)).encode("utf-8"))
        digest.update(child.read_bytes())
    return digest.hexdigest()


def dir_digest(directory: Path) -> str:
    """Digest of a Python package directory: sorted .py files only.

    Bytecode caches are excluded so the digest is stable across runs and
    machines; the guard baseline and the S22 check must agree bit for bit.
    """
    digest = hashlib.sha256()
    if not directory.is_dir():
        return ""
    for child in sorted(p for p in directory.rglob("*")
                        if p.is_file() and p.suffix == ".py"):
        digest.update(str(child.relative_to(directory)).encode("utf-8"))
        digest.update(child.read_bytes())
    return digest.hexdigest()


def discover_target(path: str | Path) -> ScanTarget | None:
    """Classify a file or directory into a scan target kind."""
    root = Path(path).expanduser()
    if not root.exists():
        return None
    if root.is_dir():
        skill_md = root / "SKILL.md"
        if skill_md.exists():
            files = tuple(sorted(p for p in root.rglob("*") if p.is_file()))
            return ScanTarget(kind="skill", name=root.name, root=root, files=files)
        return None
    name = root.name.lower()
    if re.match(r"requirements.*\.txt$", name) or name in {"pyproject.toml", "package.json"}:
        return ScanTarget(kind="deps", name=root.name, root=root, files=(root,))
    if name.endswith(".json"):
        payload = _safe_json(root)
        if isinstance(payload, dict) and ("mcpServers" in payload or "mcp" in payload):
            return ScanTarget(kind="mcp", name=root.name, root=root, files=(root,))
        if isinstance(payload, dict) and "hooks" in payload:
            return ScanTarget(kind="hook", name=root.name, root=root, files=(root,))
    if name.endswith(".toml"):
        payload = _safe_toml(root)
        if isinstance(payload, dict) and ("mcp_servers" in payload or "mcp" in payload):
            return ScanTarget(kind="mcp", name=root.name, root=root, files=(root,))
    return None


def _safe_read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _safe_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _safe_toml(path: Path) -> Any:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError):
        return None


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _decode_candidates(text: str) -> list[tuple[str, str]]:
    """Yield (decoded_text, source_tag) for base64/hex blobs found in text."""
    out: list[tuple[str, str]] = []
    for match in _BASE64_RUN_RE.finditer(text):
        blob = match.group(0)
        if len(blob) % 4 != 0:
            continue
        try:
            decoded = base64.b64decode(blob, validate=True).decode("utf-8", errors="strict")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if _PRINTABLE_RATIO_OK(decoded) and len(decoded) >= 8:
            out.append((decoded, f"base64@{match.start()}"))
    for match in _HEX_RUN_RE.finditer(text):
        blob = match.group(0)
        try:
            decoded = bytes.fromhex(blob).decode("utf-8", errors="strict")
        except (ValueError, UnicodeDecodeError):
            continue
        if _PRINTABLE_RATIO_OK(decoded) and len(decoded) >= 8:
            out.append((decoded, f"hex@{match.start()}"))
    return out


def _PRINTABLE_RATIO_OK(text: str) -> bool:
    if not text:
        return False
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\r\t")
    return printable / len(text) > 0.9


def _normalized_concat(text: str) -> str:
    """Join adjacent string literals so \"cu\"+\"rl\" style evasion still matches."""
    return _CONCAT_RE.sub("", text)


def _regex_findings(text: str, *, kind: str, file_label: str, decoded: bool = False) -> list[ScanFinding]:
    findings: list[ScanFinding] = []
    seen: set[tuple[str, str]] = set()
    for rule in static_rules(kind):
        if rule.kind != "regex" or not rule.pattern:
            continue
        for match in re.finditer(rule.pattern, text):
            key = (rule.rule_id, match.group(0)[:64])
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                ScanFinding(
                    rule_id=rule.rule_id,
                    name=rule.name,
                    severity=rule.severity,
                    action=rule.action,
                    file=file_label,
                    line=_line_of(text, match.start()),
                    evidence=match.group(0)[:160],
                    decoded=decoded,
                )
            )
    return findings


def _iter_scannable_texts(target: ScanTarget) -> list[tuple[str, str]]:
    """Return (file_label, text) pairs, including extracted code blocks."""
    texts: list[tuple[str, str]] = []
    for path in target.files:
        if path.suffix.lower() in {".png", ".jpg", ".jpeg", ".gif", ".zip", ".gz", ".pdf", ".ico"}:
            continue
        raw = _safe_read(path)
        if not raw:
            continue
        label = str(path.relative_to(target.root)) if path != target.root else target.root.name
        texts.append((label, raw))
        for block in _CODE_BLOCK_RE.findall(raw):
            texts.append((f"{label} [code-block]", block))
        for inline in _INLINE_CODE_RE.findall(raw):
            texts.append((f"{label} [inline-code]", inline))
    return texts


def _mcp_servers(payload: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(payload, dict):
        return {}
    servers = payload.get("mcpServers")
    if isinstance(servers, dict):
        return servers
    mcp = payload.get("mcp")
    if isinstance(mcp, dict):
        if isinstance(mcp.get("servers"), dict):
            return mcp["servers"]
        return {k: v for k, v in mcp.items() if isinstance(v, dict)}
    return {}


def _structural_findings(target: ScanTarget, registry: Registry, digest: str) -> list[ScanFinding]:
    findings: list[ScanFinding] = []

    def add(rule_id: str, file_label: str, evidence: str, line: int = 0) -> None:
        rule = RULES_BY_ID.get(rule_id)
        if rule is None:
            return
        findings.append(ScanFinding(
            rule_id=rule.rule_id, name=rule.name, severity=rule.severity,
            action=rule.action, file=file_label, line=line, evidence=evidence[:160],
        ))

    if target.kind == "mcp":
        payload = _safe_json(target.root) if target.root.suffix == ".json" else _safe_toml(target.root)
        for server_name, server in _mcp_servers(payload).items():
            if not isinstance(server, dict):
                continue
            args = [str(a) for a in server.get("args", [])] if isinstance(server.get("args"), list) else []
            command = str(server.get("command", ""))
            env = server.get("env") if isinstance(server.get("env"), dict) else {}
            identity = " ".join([command, *args]).strip()
            joined = " ".join(args)
            is_filesystem = "filesystem" in server_name.lower() or "filesystem" in identity.lower()
            # S13: server not in trusted registry
            if registry.lookup("mcp", server_name) is None:
                add("S13", target.root.name, f"unregistered mcp server: {server_name} ({identity[:80]})")
            # S14: filesystem server without a scoped root
            if is_filesystem:
                roots = [a for a in args if a.startswith("/") or a.startswith("~") or a.startswith(".")]
                if not roots or any(a in {"/", "~", "."} for a in roots):
                    add("S14", target.root.name, f"filesystem server '{server_name}' root not scoped: {joined[:80]}")
            # S15: traversal in args or inline secrets in env
            if _PATH_TRAVERSAL_RE.search(joined):
                add("S15", target.root.name, f"path traversal in args of '{server_name}'")
            for key, value in env.items():
                if re.search(r"(?i)(key|token|secret|password)", str(key)):
                    add("S15", target.root.name, f"inline secret in env of '{server_name}': {key}")
            # S16: server source not trusted
            if registry.lookup("mcp", server_name) is None:
                add("S16", target.root.name, f"mcp server source untrusted: {server_name}")
        registered = registry.lookup("mcp", target.name)
        if registered and registered.get("sha256") and registered["sha256"] != digest:
            add("S17", target.root.name, f"hash drift for {target.name}")

    if target.kind == "skill":
        registered = registry.lookup("skill", target.name)
        if registered is None:
            add("S16", target.root.name, f"skill source untrusted: {target.name}")
        elif registered.get("sha256") and registered["sha256"] != digest:
            add("S17", target.root.name, f"hash drift for {target.name}")

    if target.kind == "deps":
        for label, text in _iter_scannable_texts(target):
            if re.match(r"requirements.*\.txt$", label):
                for lineno, line in enumerate(text.splitlines(), start=1):
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#") or stripped.startswith("-"):
                        continue
                    package = re.split(r"[<>=!~\[;]", stripped, maxsplit=1)[0].strip()
                    if "==" not in stripped:
                        add("S18", label, f"unpinned: {stripped[:80]}", lineno)
                    if _typosquat_hit(package):
                        add("S18", label,
                            f"possible typosquat: {package} (similar to a popular package)", lineno)
            if label == "package.json":
                try:
                    payload = json.loads(text)
                except json.JSONDecodeError:
                    payload = {}
                for section in ("dependencies", "devDependencies"):
                    for pkg, spec in (payload.get(section) or {}).items():
                        if spec in {"*", "latest", "next"}:
                            add("S18", label, f"unpinned: {pkg}@{spec}")
                        if _typosquat_hit(pkg):
                            add("S18", label, f"possible typosquat: {pkg} (similar to a popular package)")
        registered = registry.lookup("deps", target.name)
        if registered and registered.get("sha256") and registered["sha256"] != digest:
            add("S17", target.root.name, f"hash drift for {target.name}")

    if target.kind == "hook":
        payload = _safe_json(target.root)
        if isinstance(payload, dict):
            approved_root = (agentsec_dir() / "hooks").resolve()
            baseline = _load_hook_baseline()
            callbacks = baseline.get("callbacks")
            callbacks = callbacks if isinstance(callbacks, dict) else {}
            for event, matchers in (payload.get("hooks") or {}).items():
                if not isinstance(matchers, list):
                    continue
                for matcher in matchers:
                    for hook in (_matcher_hooks(matcher)):
                        command = str(hook.get("command", ""))
                        if _NETWORK_FETCH_RE.search(command):
                            add("S21", target.root.name, f"hook command fetches network: {command[:80]}")
                        script = _script_path_from_command(command)
                        if script is not None:
                            resolved = script.resolve()
                            if approved_root not in resolved.parents:
                                add("S21", target.root.name,
                                    f"hook callback outside approved dir: {resolved}")
                            if resolved.exists():
                                current = sha256_path(resolved)
                                expected = callbacks.get(str(resolved))
                                expected = expected.get("sha256") if isinstance(expected, dict) else expected
                                if expected and expected != current:
                                    add("S22", target.root.name,
                                        f"hook script hash mismatch: {resolved}")
                            continue
                        # Module callbacks (python -m <module> hook ...) carry no
                        # script path: pin and re-check the package digest.
                        module = module_from_command(command)
                        if not module:
                            continue
                        record = callbacks.get(module)
                        if not isinstance(record, dict) or not record.get("sha256"):
                            add("S22", target.root.name,
                                f"hook callback module not in baseline: {module}")
                            continue
                        root = Path(str(record.get("path", "")))
                        if not root.is_dir():
                            add("S22", target.root.name,
                                f"hook callback module path missing: {root}")
                            continue
                        if dir_digest(root) != record["sha256"]:
                            add("S22", target.root.name,
                                f"hook callback module hash mismatch: {module}")
        registered = registry.lookup("hook", target.name)
        if registered and registered.get("sha256") and registered["sha256"] != digest:
            add("S17", target.root.name, f"hash drift for {target.name}")

    return findings


def _execution_origin(target: ScanTarget) -> dict[str, Any]:
    """Describe how an MCP config would resolve to executable code.

    This intentionally stops at the first executable boundary. Package
    managers and remote downloads are marked dynamic/unknown instead of being
    presented as verified dependency evidence.
    """
    if target.kind != "mcp":
        return {}
    payload = _safe_json(target.root) if target.root.suffix == ".json" else _safe_toml(target.root)
    servers = _mcp_servers(payload)
    origins: list[dict[str, Any]] = []
    for name, server in servers.items():
        if not isinstance(server, dict):
            continue
        command = str(server.get("command", ""))
        args = [str(item) for item in server.get("args", [])] if isinstance(server.get("args"), list) else []
        status = "resolved"
        reason = ""
        if command in {"npx", "npm", "pnpm", "yarn", "bun"}:
            status = "dynamic"
            reason = "package manager may download or resolve mutable content"
        elif command in {"python", "python3", "python2", "uv", "pip", "pip3"}:
            status = "unknown" if any(item in {"-m", "-c"} for item in args) else "resolved"
            reason = "module or package resolution requires runtime environment" if status == "unknown" else ""
        elif not command:
            status = "unknown"
            reason = "MCP command is missing"
        origins.append({"server": name, "command": command, "args": args,
                        "executable": command, "resolution_status": status,
                        "unknown_reason": reason})
    return {"servers": origins, "resolution_status": (
        "unknown" if any(item["resolution_status"] == "unknown" for item in origins)
        else "dynamic" if any(item["resolution_status"] == "dynamic" for item in origins)
        else "resolved")}


def _matcher_hooks(matcher: Any) -> list[dict[str, Any]]:
    if not isinstance(matcher, dict):
        return []
    hooks = matcher.get("hooks")
    if not isinstance(hooks, list):
        return []
    return [h for h in hooks if isinstance(h, dict)]


_INTERPRETER_RE = re.compile(
    r"(?:python[0-9.]*|node|bash|sh|zsh|pwsh|powershell|ruby|perl)\s+([^\s\"']+\.(?:py|sh|ps1|js|mjs))"
)
_LOCAL_SCRIPT_RE = re.compile(r"((?:~|/|\./|%USERPROFILE%)[^\s\"']*\.(?:py|sh|ps1|js|mjs))")
_URL_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://\S+")


def _script_path_from_command(command: str) -> Path | None:
    match = _INTERPRETER_RE.search(command)
    if match is None:
        # URLs are not local callback scripts; strip them before path matching.
        match = _LOCAL_SCRIPT_RE.search(_URL_RE.sub(" ", command))
    if match is None:
        return None
    candidate = match.group(1).replace("\\", "/")
    if candidate.startswith("~") or candidate.startswith("%USERPROFILE%"):
        return Path(candidate.replace("%USERPROFILE%", "~")).expanduser()
    return Path(candidate)


def _load_hook_baseline() -> dict[str, Any]:
    """Guard-written hook baseline (settings hash + pinned callback digests).

    Honors ``AGENTSEC_HOME`` like the rest of the package; the file layout
    must stay in sync with ``guard._write_baseline``.
    """
    path = agentsec_dir() / "hook-baseline.json"
    if not path.exists():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _typosquat_hit(package: str) -> bool:
    normalized = re.sub(r"[-_]", "", package.lower())
    return any(_close_name(normalized, popular) for popular in POPULAR_PACKAGES)


def _close_name(candidate: str, popular: str) -> bool:
    """Cheap edit-distance check for typosquat detection."""
    if abs(len(candidate) - len(popular)) > 2:
        return False
    if candidate == popular:
        return False
    distance = _levenshtein(candidate, popular)
    return distance <= 2 and distance < len(popular) / 2 + 1


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def _dedupe_findings(findings: list[ScanFinding]) -> list[ScanFinding]:
    """Collapse duplicates across text sources (raw / code-block / decoded)."""
    by_evidence: dict[tuple[str, str], ScanFinding] = {}
    for finding in findings:
        key = (finding.rule_id, finding.evidence[:64])
        if key not in by_evidence:
            by_evidence[key] = finding
    seen_lines: set[tuple[str, str, int]] = set()
    collapsed: list[ScanFinding] = []
    for finding in by_evidence.values():
        base_file = finding.file.split(" [")[0]
        if finding.line:
            line_key = (finding.rule_id, base_file, finding.line)
            if line_key in seen_lines:
                continue
            seen_lines.add(line_key)
        collapsed.append(finding)
    return sorted(collapsed, key=lambda f: (f.file, f.line, f.rule_id))


def scan_target(
    target: ScanTarget,
    *,
    host: str = "",
    registry: Registry | None = None,
) -> ScanReport:
    registry = registry or Registry.load()
    digest = sha256_path(target.root)
    content_hash = normalized_content_hash(target.root)
    findings: list[ScanFinding] = []

    for label, text in _iter_scannable_texts(target):
        findings.extend(_regex_findings(text, kind=target.kind, file_label=label))
        normalized = _normalized_concat(text)
        if normalized != text:
            findings.extend(_regex_findings(normalized, kind=target.kind,
                                            file_label=f"{label} [normalized]"))
        for decoded, tag in _decode_candidates(text):
            findings.extend(_regex_findings(decoded, kind=target.kind,
                                            file_label=f"{label} [decoded:{tag}]", decoded=True))

    findings.extend(_structural_findings(target, registry, digest))
    findings = _dedupe_findings(findings)

    registered_entry = registry.lookup(target.kind, target.name)
    registered = registered_entry is not None
    drift = bool(registered_entry and registered_entry.get("sha256")
                 and registered_entry["sha256"] != digest)

    carrier = classify_carrier(target.root)
    state = state_for_carrier(carrier)
    product = infer_product(target.root)
    logical_id, instance_id = derive_ids(
        product=product, kind=target.kind, name=target.name, host=host,
        carrier=carrier, path=str(target.root),
    )
    inventory_only = (state not in {AssetState.INSTALLED, AssetState.ENABLED, AssetState.ACTIVE}
                      or carrier == AssetCarrier.SYNTHETIC)
    scope = "project" if carrier == AssetCarrier.PROJECT_LOCAL else "host"
    verdict = scan_policy_verdict(findings)
    score = score_findings(findings, state=state.value)
    risk_assessment = score["assessment"]
    assessment_reason = score["reason"]

    return ScanReport(
        scan_id=f"scan-{digest[:16]}-{utc_now_iso()}",
        ts=utc_now_iso(),
        host=host,
        target_kind=AssetKind(target.kind),
        target_name=target.name,
        target_path=str(target.root),
        sha256=digest,
        findings=findings,
        verdict=verdict,
        registered=registered,
        drift=drift,
        risk_assessment=risk_assessment,
        assessment_reason=assessment_reason,
        risk_score=score["score"],
        ranking_score=score["ranking_score"],
        risk_breakdown=score["breakdown"],
        product=product,
        logical_id=logical_id,
        instance_id=instance_id,
        content_hash=content_hash,
        carrier=carrier,
        state=state,
        scope=scope,
        inventory_only=inventory_only,
        execution_origin=_execution_origin(target),
    )


def scan_path(path: str | Path, *, host: str = "", registry: Registry | None = None,
              unchanged_hashes: dict[str, str] | None = None) -> list[ScanReport]:
    """Scan a file or recursively discover Skills/configs under an asset root.

    Dependency/vendor/cache directories are pruned so a home-level inventory
    does not scan package contents, Git object stores, or Python environments.
    """
    root = Path(path).expanduser()
    if not root.exists():
        return []
    registry = registry or Registry.load()
    direct = discover_target(root)
    if direct is not None:
        return [scan_target(direct, host=host, registry=registry)]
    if not root.is_dir():
        return []

    excluded_dirs = {
        ".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv",
        "venv", "env", ".cache", "cache", "dist", "build",
    }
    candidate_names = {
        ".mcp.json", "mcp.json", "mcp_config.json", "claude_desktop_config.json",
        "config.toml", "settings.json", "settings.local.json", "hooks.json",
        "package.json", "pyproject.toml",
    }
    targets_by_root: dict[str, ScanTarget] = {}
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        dirs[:] = sorted(name for name in dirs if name not in excluded_dirs)
        current_path = Path(current)
        if "SKILL.md" in files:
            found = discover_target(current_path)
            if found is not None:
                targets_by_root[str(found.root)] = found
        for name in sorted(files):
            if name not in candidate_names and not re.match(r"requirements.*\.txt$", name):
                continue
            candidate = discover_target(current_path / name)
            if candidate is not None:
                targets_by_root[str(candidate.root)] = candidate
    targets = [targets_by_root[key] for key in sorted(targets_by_root)]
    reports: list[ScanReport] = []
    for target in targets:
        if unchanged_hashes is not None:
            try:
                digest = sha256_path(target.root)
            except OSError:
                digest = ""
            if digest and unchanged_hashes.get(str(target.root.resolve())) == digest:
                continue
        report = scan_target(target, host=host, registry=registry)
        reports.append(report)
        if unchanged_hashes is not None:
            unchanged_hashes[str(target.root.resolve())] = report.sha256
    return reports
