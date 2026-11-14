"""端侧产品加载验证：装到产品真实技能目录，起一次真实会话判定是否加载。

为什么在端侧做：控制面进程通常连不到被测主机（NAT、分离部署、无免密）。
所以这条验证由端侧自己执行，再把证据回传控制面
（``POST /api/v1/admissions/<id>/product-verification``）。控制面只记录，不代为声称。

用法::

    python3 -m endpoint.probe_product install <package_dir> --product qwen-code --name demo
    python3 -m endpoint.probe_product verify  --product qwen-code --name demo
    python3 -m endpoint.probe_product remove  --product qwen-code --name demo

每次输出一行 JSON。``loaded`` 是三态：True 产品会话确认、False 产品否认、
null 探测没给出结论（超时/缺凭据/无 CLI）——null 不等于未加载。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

SKILL_ROOT = {
    "claude-code": ".claude/skills",
    "codex": ".codex/skills",
    "qwen-code": ".qwen/skills",
}

# 只有实测过的产品才给探测命令；没测过的产品不做会话级验证，直接降级。
PROBE_COMMAND = {
    "claude-code": ("claude", "-p", "/{name}", "--output-format", "text"),
    "qwen-code": ("qwen", "-y", "-p", "/{name}"),
}

MCP_CONFIG_FILES = {
    "claude-code": (".claude.json", ".claude/settings.json", ".claude/.mcp.json"),
    "qwen-code": (".qwen/settings.json",),
    "codex": (".codex/config.toml",),
}

MCP_LIST_COMMAND = {
    "claude-code": ("claude", "mcp", "list"),
    "qwen-code": ("qwen", "mcp", "list"),
    "codex": ("codex", "mcp", "list"),
}

UNLOADED_MARKERS = ("unknown command", "unknown skill", "no such command", "not found:")
PROBE_TIMEOUT = 120
FIRST_INSTALL = "first_install"


def _file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(1 << 20)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def tree_hash(directory: Path) -> str:
    """与控制面 ManagedInstaller.tree_hash 同一算法：相对路径 + sha256 + 权限位。

    两边算法必须一致，否则端侧算出的哈希永远对不上审批声明，验证会被误判成
    content_drift。
    """
    directory = Path(directory)
    entries = []
    for current, dirs, files in os.walk(directory, followlinks=False):
        base = Path(current)
        for name in sorted(dirs):
            path = base / name
            if path.is_symlink():
                raise ValueError("installer_symlink_forbidden")
            entries.append("d\0" + path.relative_to(directory).as_posix())
        for name in sorted(files):
            path = base / name
            if path.is_symlink() or not path.is_file():
                raise ValueError("installer_non_regular_file")
            mode = path.stat().st_mode & 0o7777
            entries.append("f\0{}\0{}\0{:o}".format(
                path.relative_to(directory).as_posix(), _file_hash(path), mode))
    return hashlib.sha256("\n".join(entries).encode("utf-8")).hexdigest()


def _target(product: str, name: str) -> Path:
    relative = SKILL_ROOT.get(product)
    if relative is None:
        raise SystemExit(f"unknown_product: {product}")
    if not name or "/" in name or name.startswith("."):
        raise SystemExit("invalid_asset_name")
    return Path.home() / relative / name


def _snapshot_dir(product: str) -> Path:
    return Path.home() / ".asgp" / "backup" / "product" / product


def install(product: str, name: str, package: Path) -> dict:
    package = Path(package)
    if not package.is_dir():
        raise SystemExit("installer_source_missing")
    target = _target(product, name)
    root = target.parent
    root.mkdir(parents=True, exist_ok=True)
    if target.is_symlink():
        raise SystemExit("installer_symlink_forbidden")

    rollback = FIRST_INSTALL
    backup = None
    if target.exists():
        store = _snapshot_dir(product)
        store.mkdir(parents=True, exist_ok=True)
        backup = store / f"{name}-{int(time.time())}"
        os.replace(target, backup)
        rollback = str(backup)

    temporary = root / f".asgp-probe-{os.getpid()}"
    try:
        shutil.copytree(package, temporary, symlinks=False)
        os.replace(temporary, target)
        observed = tree_hash(target)
    except BaseException:
        if temporary.exists():
            shutil.rmtree(temporary, ignore_errors=True)
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
        if backup is not None and backup.exists():
            os.replace(backup, target)
        raise
    return {"action": "install", "target": str(target), "observed_hash": observed,
            "rollback_ref": rollback}


def _skill_invocation_name(target: Path) -> str:
    """产品认的是 SKILL.md frontmatter 的 name，不是安装目录名。

    实测：目录叫 ``inst_xxx``、frontmatter 写 ``name: asgp-qwen-admission`` 时，
    ``/inst_xxx`` 回 Unknown command，``/asgp-qwen-admission`` 才执行。安装目录
    必须用实例标识（唯一、可审计），所以探测命令必须回读清单里的 name。
    """
    try:
        text = (target / "SKILL.md").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return ""
    for line in lines[1:]:
        stripped = line.strip()
        if stripped == "---":
            break
        if stripped.lower().startswith("name:"):
            return stripped.split(":", 1)[1].strip().strip('"').strip("'")
    return ""


def verify(product: str, name: str, expected_hash: str | None = None) -> dict:
    target = _target(product, name)
    if not target.is_dir():
        raise SystemExit("product_not_installed")
    manifest = target / "SKILL.md"
    if not manifest.is_file():
        raise SystemExit("product_manifest_missing")
    observed = tree_hash(target)
    if expected_hash and observed != expected_hash:
        raise SystemExit("product_content_mismatch")

    result = {"action": "verify", "target": str(target), "observed_hash": observed,
              "level": "filesystem", "loaded": None, "probe": "not_run"}
    template = PROBE_COMMAND.get(product)
    if template is None:
        result["probe"] = "unsupported_for_product"
        return result
    invocation = _skill_invocation_name(target) or name
    result["skill_invocation"] = invocation
    command = tuple(part.format(name=invocation) for part in template)
    executable = shutil.which(command[0])
    if executable is None:
        result["probe"] = "cli_not_found"
        return result
    try:
        completed = subprocess.run(
            (executable,) + command[1:],
            cwd="/tmp", capture_output=True, text=True, timeout=PROBE_TIMEOUT, check=False,
            env={**os.environ, "NO_COLOR": "1", "TERM": "dumb"},
        )
    except subprocess.TimeoutExpired:
        # 超时只说明没得出结论，不能当"产品否认该技能"。
        result.update(level="product_session", probe={"outcome": "timeout"})
        return result
    output = ((completed.stdout or "") + (completed.stderr or ""))[-4000:]
    lowered = output.lower()
    if any(marker in lowered for marker in UNLOADED_MARKERS):
        loaded, outcome = False, "not_loaded"
    elif completed.returncode == 0:
        loaded, outcome = True, "loaded"
    else:
        loaded, outcome = None, "inconclusive"
    result.update(level="product_session", loaded=loaded,
                  probe={"outcome": outcome, "exit_code": completed.returncode,
                         "output_head": output[:300]})
    return result


def remove(product: str, name: str, rollback_ref: str | None = None) -> dict:
    target = _target(product, name)
    out = {"action": "remove", "target": str(target), "outcome": "noop"}
    if rollback_ref and rollback_ref != FIRST_INSTALL and Path(rollback_ref).is_dir():
        if target.exists():
            shutil.rmtree(target)
        os.replace(Path(rollback_ref), target)
        out["outcome"] = "restored"
        return out
    if target.exists():
        shutil.rmtree(target)
        out["outcome"] = "removed"
    return out



def _extract_toml_mcp_entry(text: str, name: str):
    """从 Codex config.toml 提取 mcp_servers.<name> 配置块，兼容 Python 3.10+。"""
    try:
        import tomllib  # type: ignore[import-not-found]
        parsed = tomllib.loads(text)
        servers = parsed.get("mcp_servers")
        if isinstance(servers, dict) and isinstance(servers.get(name), dict):
            return servers[name]
    except ModuleNotFoundError:
        import re as _re
        hdr = _re.compile(rf'^\[mcp_servers\.(?:"{_re.escape(name)}"|{_re.escape(name)})\]\s*$')
        collecting = False
        section_data = {}
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("["):
                if collecting:
                    break
                if hdr.match(stripped):
                    collecting = True
                continue
            if collecting and "=" in stripped:
                k, v = stripped.split("=", 1)
                section_data[k.strip()] = v.strip().strip('"').strip("'")
        if collecting:
            return section_data
    except Exception:
        return None
    return None


def _find_mcp_entry(product: str, name: str, home: Path | None = None):
    rel_paths = MCP_CONFIG_FILES.get(product)
    if rel_paths is None:
        raise SystemExit(f"unknown_product: {product}")
    if not name or "/" in name or name.startswith("."):
        raise SystemExit("invalid_asset_name")
    base = Path(home) if home is not None else Path.home()
    for rel in rel_paths:
        cfg_path = base / rel
        if not cfg_path.is_file() or cfg_path.is_symlink():
            continue
        try:
            text = cfg_path.read_text(encoding="utf-8")
        except OSError:
            continue
        if cfg_path.suffix == ".toml":
            entry = _extract_toml_mcp_entry(text, name)
            if entry is not None:
                return cfg_path, entry
        else:
            try:
                parsed = json.loads(text)
            except ValueError:
                continue
            servers = parsed.get("mcpServers") if isinstance(parsed, dict) else None
            if isinstance(servers, dict) and isinstance(servers.get(name), dict):
                return cfg_path, servers[name]
    return base / rel_paths[0], None


def verify_mcp(product: str, name: str, expected_hash: str | None = None, *, home: Path | None = None) -> dict:
    """验证 mcp_server 是否已写入产品真实配置，并尽可能用 `<product> mcp list` 复核。"""
    cfg_path, entry = _find_mcp_entry(product, name, home=home)
    if entry is None:
        return {
            "action": "verify",
            "asset_type": "mcp_server",
            "target": str(cfg_path),
            "observed_hash": None,
            "level": "filesystem",
            "loaded": False,
            "probe": "not_registered",
        }
    canonical = json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    observed = hashlib.sha256(canonical).hexdigest()
    if expected_hash and observed != expected_hash:
        raise SystemExit("product_content_mismatch")

    result = {
        "action": "verify",
        "asset_type": "mcp_server",
        "target": str(cfg_path),
        "observed_hash": observed,
        "level": "filesystem",
        "loaded": None,
        "probe": "config_registered",
    }
    command = MCP_LIST_COMMAND.get(product)
    if command is None:
        result["probe"] = "unsupported_for_product"
        return result
    executable = shutil.which(command[0])
    if executable is None:
        result["probe"] = "cli_not_found"
        return result
    try:
        completed = subprocess.run(
            (executable,) + command[1:],
            cwd="/tmp", capture_output=True, text=True, timeout=PROBE_TIMEOUT, check=False,
            env={**os.environ, "NO_COLOR": "1", "TERM": "dumb"},
        )
    except subprocess.TimeoutExpired:
        result.update(level="product_session", probe={"outcome": "timeout"})
        return result
    output = ((completed.stdout or "") + "\n" + (completed.stderr or ""))[-4000:]
    if completed.returncode == 0:
        import re as _re
        listed = bool(_re.search(rf"(?<![A-Za-z0-9_-]){_re.escape(name)}(?![A-Za-z0-9_-])", output))
        loaded = listed
        outcome = "listed" if listed else "not_listed"
    else:
        loaded, outcome = None, "inconclusive"
    result.update(
        level="product_session",
        loaded=loaded,
        probe={"outcome": outcome, "exit_code": completed.returncode, "output_head": output[:300]},
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("install", "verify", "remove"))
    parser.add_argument("package", nargs="?", default="")
    parser.add_argument("--product", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--expected-hash", default="")
    parser.add_argument("--rollback-ref", default="")
    parser.add_argument("--asset-type", choices=("skill", "mcp_server"), default="skill")
    args = parser.parse_args()
    try:
        if args.action == "install":
            result = install(args.product, args.name, Path(args.package))
        elif args.action == "verify":
            if args.asset_type == "mcp_server":
                result = verify_mcp(args.product, args.name, args.expected_hash or None)
            else:
                result = verify(args.product, args.name, args.expected_hash or None)
        else:
            result = remove(args.product, args.name, args.rollback_ref or None)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 - 端侧要把失败原因原样交给控制面
        result = {"action": args.action, "error": type(exc).__name__, "detail": str(exc)[:200]}
    result.update(product_id=args.product, name=args.name)
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
