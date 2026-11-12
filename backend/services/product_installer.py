"""产品加载路径安装器：把准入通过的包放进产品真的会扫描的技能目录。

平台托管目录（ManagedInstaller）只证明"平台存了包"。本模块回答另一个问题：
"产品会不会加载它"。两者不是同一件事，验收证据必须来自产品侧。

验证分两级，降级必须如实标注：

1. ``filesystem``：目标目录、``SKILL.md`` 清单、目录树哈希。
2. ``product_session``：真的起一次产品会话（``claude -p /<name>``），按产品
   是否认识这个技能判定。没有实测过探测命令的产品不声明这一级，返回
   ``probe unsupported_for_product``，绝不把文件存在说成"已加载"。

约束：
- 产品根目录来自配置白名单，不接受请求体传入路径。
- 目录名只允许单个安全分量；目标是符号链接时直接拒绝，避免写到白名单外。
- 提交是原子的：先在同级暂存，再 ``os.replace``，失败恢复旧版本快照。
- 产品会话探测会消耗该用户的模型额度，因此有超时、输出截断和只在 verify
  显式触发时才运行。
"""
from __future__ import annotations

import os
import shutil
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path

from services.managed_installer import (
    FIRST_INSTALL,
    InstallerError,
    component,
    tree_hash,
)

# 产品技能目录布局；只有这里列出的产品允许安装。
SKILL_ROOT = {
    "claude-code": ".claude/skills",
    "codex": ".codex/skills",
    "qwen-code": ".qwen/skills",
}

# 产品不认识某个斜杠命令时的输出特征。命中即判"未加载"。
UNLOADED_MARKERS = ("unknown command", "unknown skill", "no such command", "not found:")

# 只有经过实测的产品才声明会话级探测；其余产品明确降级到 filesystem。
PROBE_COMMAND = {
    "claude-code": ("claude", "-p", "/{name}", "--output-format", "text"),
}

PROBE_TIMEOUT = 120
PROBE_OUTPUT_LIMIT = 4000


@dataclass(frozen=True)
class ProductBinding:
    """一台主机上某个产品的技能根目录绑定。"""

    product_id: str
    home: str
    owner: str | None = None

    @property
    def skills_root(self) -> Path:
        relative = SKILL_ROOT.get(self.product_id)
        if relative is None:
            raise InstallerError("unknown_product", 400)
        return Path(self.home) / relative


def parse_bindings(raw: str | None) -> list[ProductBinding]:
    """解析 ``ASGP_PRODUCT_BINDINGS`` JSON；格式错误直接失败，不静默忽略。"""
    import json

    if not raw or not raw.strip():
        return []
    try:
        items = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"ASGP_PRODUCT_BINDINGS is not valid JSON: {exc}") from exc
    if not isinstance(items, list):
        raise ValueError("ASGP_PRODUCT_BINDINGS must be a JSON array")
    bindings: list[ProductBinding] = []
    for item in items:
        if not isinstance(item, dict) or "product_id" not in item or "home" not in item:
            raise ValueError("each binding requires product_id and home")
        bindings.append(
            ProductBinding(
                product_id=str(item["product_id"]),
                home=str(item["home"]),
                owner=str(item["owner"]) if item.get("owner") else None,
            )
        )
    return bindings


class ProductInstaller:
    """在受控的产品技能目录里安装、校验、回滚单个技能包。"""

    def __init__(self, bindings, backup_root):
        self.backup_root = Path(backup_root)
        self._bindings: dict[str, ProductBinding] = {}
        for binding in bindings:
            if binding.product_id in self._bindings:
                raise ValueError(f"duplicate product binding: {binding.product_id}")
            # 构造时校验一次，避免运行期才发现配了不支持的产品。
            _ = binding.skills_root
            self._bindings[binding.product_id] = binding

    # --- 查询 ---------------------------------------------------------------

    def products(self) -> list[str]:
        return sorted(self._bindings)

    def target(self, product_id: str, name: str) -> Path:
        binding = self._binding(product_id)
        component(name, "asset_name")
        return binding.skills_root / name

    def supports_session_probe(self, product_id: str) -> bool:
        return product_id in PROBE_COMMAND

    def _binding(self, product_id: str) -> ProductBinding:
        binding = self._bindings.get(product_id)
        if binding is None:
            raise InstallerError("unknown_product", 400)
        return binding

    # --- 安装 ---------------------------------------------------------------

    def install(self, product_id: str, name: str, staging, expected_hash: str) -> dict:
        """把暂存内容放进产品技能目录，返回落盘哈希与回滚凭据。

        回滚凭据与平台安装器同义：``first_install`` 表示此前没有旧版本，
        其余是提交前快照名。
        """
        binding = self._binding(product_id)
        target = self.target(product_id, name)
        staging = Path(staging)
        if not staging.is_dir():
            raise InstallerError("installer_not_staged")
        if tree_hash(staging) != expected_hash:
            raise InstallerError("content_drift")
        root = target.parent
        root.mkdir(parents=True, exist_ok=True)
        if target.is_symlink():
            raise InstallerError("installer_symlink_forbidden")

        snapshot: Path | None = None
        rollback_ref = FIRST_INSTALL
        if target.exists():
            snapshot = self._snapshot(product_id, name)
            os.replace(target, snapshot)
            rollback_ref = snapshot.name

        temporary = root / f".asgp-stage-{uuid.uuid4().hex[:12]}"
        try:
            shutil.copytree(staging, temporary, symlinks=False)
            self._chown(temporary, binding.owner)
            os.replace(temporary, target)
            observed = tree_hash(target)
            if observed != expected_hash:
                raise InstallerError("installer_commit_mismatch")
        except BaseException:
            if temporary.exists():
                shutil.rmtree(temporary, ignore_errors=True)
            if target.exists() and snapshot is not None:
                shutil.rmtree(target, ignore_errors=True)
            if snapshot is not None and snapshot.exists():
                os.replace(snapshot, target)
            raise
        return {
            "product_id": product_id,
            "target": str(target),
            "observed_hash": observed,
            "rollback_ref": rollback_ref,
        }

    # --- 验证 ---------------------------------------------------------------

    def verify(self, product_id: str, name: str, expected_hash: str, *, probe: bool = True) -> dict:
        """校验产品侧内容；可选再起一次真实会话确认产品认识这个技能。

        ``loaded`` 只有在会话级探测通过时才为 True。文件级校验通过但会话不可
        用时返回 ``loaded=None`` 与 ``level=filesystem``，调用方必须按"未验证
        加载"处理，不得当成已生效。
        """
        binding = self._binding(product_id)
        target = self.target(product_id, name)
        if not target.is_dir():
            raise InstallerError("product_not_installed")
        manifest = target / "SKILL.md"
        if not manifest.is_file():
            raise InstallerError("product_manifest_missing")
        observed = tree_hash(target)
        if observed != expected_hash:
            raise InstallerError("product_content_mismatch")

        result = {
            "product_id": product_id,
            "target": str(target),
            "observed_hash": observed,
            "level": "filesystem",
            "loaded": None,
            "probe": "not_requested",
        }
        if not probe:
            return result
        template = PROBE_COMMAND.get(product_id)
        if template is None:
            result["probe"] = "unsupported_for_product"
            return result
        invocation = _manifest_name(manifest) or name
        result["skill_invocation"] = invocation
        command = tuple(part.format(name=invocation) for part in template)
        executable = _resolve_command(command[0], binding.home)
        if executable is None:
            result["probe"] = "cli_not_found"
            return result
        invocation = (executable,) + command[1:]
        result["probe"] = self._run_probe(invocation, binding, command)
        result["level"] = result["probe"].pop("level")
        result["loaded"] = result["probe"].pop("loaded")
        return result

    def _run_probe(self, invocation, binding: ProductBinding, command) -> dict:
        environment = {
            "HOME": binding.home,
            "PATH": f"{Path(binding.home) / '.local/npm/node_modules/.bin'}:/usr/local/bin:/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "TERM": "dumb",
            # 产品会从用户配置读供应商凭据；这里不额外注入密钥。
            "NO_COLOR": "1",
        }
        try:
            completed = subprocess.run(
                invocation,
                cwd="/tmp",
                env=environment,
                capture_output=True,
                text=True,
                timeout=PROBE_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired:
            # 超时不等于产品否认该技能，只说明这次会话没能得出结论。
            return {"level": "product_session", "loaded": None, "outcome": "timeout",
                    "command": list(command)}
        except OSError as exc:
            return {"level": "product_session", "loaded": None, "outcome": "exec_error",
                    "error": type(exc).__name__, "command": list(command)}

        output = ((completed.stdout or "") + (completed.stderr or ""))[-PROBE_OUTPUT_LIMIT:]
        lowered = output.lower()
        # 三态判定，不能把"探测环境不可用"当成"产品不认识这个技能"：
        # 明确报 unknown command 才是 not_loaded；非零但没这个特征只能算
        # inconclusive（缺凭据、网络失败、模型报错），一律降级为未验证。
        explicitly_unloaded = any(marker in lowered for marker in UNLOADED_MARKERS)
        if explicitly_unloaded:
            loaded, outcome = False, "not_loaded"
        elif completed.returncode == 0:
            loaded, outcome = True, "loaded"
        else:
            loaded, outcome = None, "inconclusive"
        return {
            "level": "product_session",
            "loaded": loaded,
            "outcome": outcome,
            "command": list(command),
            "exit_code": completed.returncode,
            "output_head": output[:400],
        }

    # --- 回滚 ---------------------------------------------------------------

    def remove(self, product_id: str, name: str, rollback_ref: str | None) -> str:
        """撤销产品目录里的安装后果，返回 restored/removed/noop。"""
        binding = self._binding(product_id)
        target = self.target(product_id, name)
        if rollback_ref is None:
            return "noop"
        if rollback_ref != FIRST_INSTALL:
            snapshot = self._snapshot_path(product_id, name, rollback_ref)
            if snapshot.is_dir():
                if target.exists():
                    shutil.rmtree(target)
                os.replace(snapshot, target)
                self._chown(target, binding.owner)
                return "restored"
        if target.exists():
            shutil.rmtree(target)
            return "removed"
        return "noop"

    # --- 内部 ---------------------------------------------------------------

    def _snapshot_path(self, product_id: str, name: str, reference: str) -> Path:
        return self.backup_root / "product" / product_id / name / reference

    def _snapshot(self, product_id: str, name: str) -> Path:
        root = self.backup_root / "product" / product_id / name
        root.mkdir(parents=True, exist_ok=True)
        target = root / f"{uuid.uuid4().hex[:12]}"
        while target.exists():
            target = root / f"{uuid.uuid4().hex[:12]}"
        return target

    @staticmethod
    def _chown(path: Path, owner: str | None) -> None:
        """把安装内容交给目标用户；不配置 owner 时保持平台权限。"""
        if not owner:
            return
        try:
            import pwd

            entry = pwd.getpwnam(owner)
        except KeyError as exc:
            raise InstallerError("unknown_owner", 400) from exc
        for current, dirs, files in os.walk(path):
            os.chown(current, entry.pw_uid, entry.pw_gid)
            for item in dirs + files:
                os.chown(Path(current) / item, entry.pw_uid, entry.pw_gid, follow_symlinks=False)


def _manifest_name(manifest: Path) -> str:
    """读 SKILL.md frontmatter 的 name——产品的斜杠命令用的是它，不是目录名。

    实测：目录叫 ``inst_xxx``、清单写 ``name: asgp-demo`` 时，``/inst_xxx`` 回
    Unknown command、``/asgp-demo`` 才执行。安装目录必须用实例标识（唯一、可
    审计），所以探测命令只能回读清单里的 name。
    """
    try:
        lines = manifest.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""
    if not lines or lines[0].strip() != "---":
        return ""
    for line in lines[1:]:
        stripped = line.strip()
        if stripped == "---":
            break
        if stripped.lower().startswith("name:"):
            return stripped.split(":", 1)[1].strip().strip('"').strip("'")
    return ""


def _resolve_command(name: str, home: str) -> str | None:
    """在目标用户的常用 bin 目录里找可执行文件，不依赖控制面自己的 PATH。"""
    for directory in (
        Path(home) / ".local/npm/node_modules/.bin",
        Path(home) / ".local/bin",
        Path("/usr/local/bin"),
        Path("/usr/bin"),
    ):
        candidate = directory / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    found = shutil.which(name)
    return found
