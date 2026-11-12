"""受管安装器：在受限托管目录内完成真实 stage/commit/verify/rollback。

准入状态机不得由客户端布尔值推进：stage/commit/verify 每次转移都必须有
文件系统后果，哈希与审批不一致时进入 failed，不用空状态跳转伪造安装成功。
托管目录之外的路径一律拒绝；符号链接、setuid/setgid 和非普通文件不进入
安装内容。托管目录是平台自己的包管理存储，不代表 Agent 产品已加载该包。
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import uuid
from datetime import datetime, timezone
from pathlib import Path

COMPONENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
CHUNK = 1024 * 1024
FIRST_INSTALL = "first_install"


class InstallerError(Exception):
    def __init__(self, code: str, status: int = 409):
        self.code, self.status = code, status
        super().__init__(code)


def component(value, field: str) -> str:
    """安装器用作目录名的标识符只允许单个安全分量。"""
    if not isinstance(value, str) or not COMPONENT.match(value):
        raise InstallerError(f"invalid_{field}", 400)
    return value


def _file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            block = handle.read(CHUNK)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def _reject_unsafe_source(source: Path) -> None:
    for current, dirs, files in os.walk(source, followlinks=False):
        base = Path(current)
        for name in dirs + files:
            path = base / name
            if path.is_symlink():
                raise InstallerError("installer_symlink_forbidden")
            mode = path.stat().st_mode
            if mode & 0o6000:
                raise InstallerError("installer_setuid_forbidden")
            if name in files and not path.is_file():
                raise InstallerError("installer_non_regular_file")


def tree_hash(directory: Path) -> str:
    """目录内容哈希：相对路径 + 文件 sha256 + 权限位，排序后确定性计算。

    符号链接和 non-regular 文件直接拒绝：安装内容必须是自包含的普通文件。
    """
    entries: list[str] = []
    for current, dirs, files in os.walk(directory, followlinks=False):
        base = Path(current)
        for name in sorted(dirs):
            path = base / name
            if path.is_symlink():
                raise InstallerError("installer_symlink_forbidden")
            entries.append("d\0" + path.relative_to(directory).as_posix())
        for name in sorted(files):
            path = base / name
            if path.is_symlink() or not path.is_file():
                raise InstallerError("installer_non_regular_file")
            mode = path.stat().st_mode & 0o7777
            entries.append("f\0{}\0{}\0{:o}".format(
                path.relative_to(directory).as_posix(), _file_hash(path), mode))
    return hashlib.sha256("\n".join(entries).encode("utf-8")).hexdigest()


class ManagedInstaller:
    """把 inbound 内容经 staging 安装到 installed，并保留可回滚快照。"""

    def __init__(self, root):
        self.root = Path(root).resolve()
        for name in ("inbound", "staging", "installed", "backup"):
            (self.root / name).mkdir(parents=True, exist_ok=True)

    def _confine(self, relative, *, base: str) -> Path:
        if not isinstance(relative, str) or not relative.strip():
            raise InstallerError("installer_path_required", 400)
        candidate = Path(relative)
        if candidate.is_absolute() or ".." in candidate.parts:
            raise InstallerError("installer_path_escape", 400)
        allowed = (self.root / base).resolve()
        resolved = (allowed / candidate).resolve()
        if resolved == allowed or allowed not in resolved.parents:
            raise InstallerError("installer_path_escape", 400)
        return resolved

    def _backup_for(self, asset_instance_id: str, transaction_id: str) -> Path:
        root = self.root / "backup" / asset_instance_id
        root.mkdir(parents=True, exist_ok=True)
        target = root / transaction_id
        while target.exists():
            target = root / f"{transaction_id}.{uuid.uuid4().hex[:8]}"
        return target

    def stage(self, transaction_id: str, source_relative: str) -> str:
        """把 inbound 下的包复制进暂存区，返回暂存内容的实测哈希。"""
        component(transaction_id, "transaction_id")
        source = self._confine(source_relative, base="inbound")
        if not source.is_dir():
            raise InstallerError("installer_source_missing", 404)
        staging = self.root / "staging" / transaction_id
        if staging.exists():
            shutil.rmtree(staging)
        _reject_unsafe_source(source)
        shutil.copytree(source, staging, symlinks=True)
        return tree_hash(staging)

    def commit(self, transaction_id: str, asset_instance_id: str, expected_hash: str) -> tuple[str, str]:
        """提交暂存内容；提交前复核哈希，旧版本先快照再原子替换。

        返回 (落盘实测哈希, 回滚凭据)。凭据是提交前快照名；首次安装没有
        旧版本可快照，凭据为 first_install，回滚即移除。
        """
        component(transaction_id, "transaction_id")
        component(asset_instance_id, "asset_instance_id")
        staging = self.root / "staging" / transaction_id
        if not staging.is_dir():
            raise InstallerError("installer_not_staged")
        if tree_hash(staging) != expected_hash:
            raise InstallerError("content_drift")
        installed = self.root / "installed" / asset_instance_id
        rollback_ref = FIRST_INSTALL
        backup = None
        if installed.exists():
            backup = self._backup_for(asset_instance_id, transaction_id)
            rollback_ref = backup.name
            os.replace(installed, backup)
        try:
            os.replace(staging, installed)
            observed = tree_hash(installed)
            if observed != expected_hash:
                raise InstallerError("installer_commit_mismatch")
        except InstallerError:
            if installed.exists():
                shutil.rmtree(installed)
            if backup is not None:
                os.replace(backup, installed)
            raise
        return observed, rollback_ref

    def verify(self, asset_instance_id: str) -> str:
        """重算已安装内容的哈希；不修改任何状态。"""
        component(asset_instance_id, "asset_instance_id")
        installed = self.root / "installed" / asset_instance_id
        if not installed.is_dir():
            raise InstallerError("installer_not_installed")
        return tree_hash(installed)

    def rollback(self, asset_instance_id: str, rollback_ref: str | None) -> str:
        """撤销一次已提交事务的安装后果，返回 restored/removed/noop。

        rollback_ref 为 None 表示该事务从未提交，只丢弃暂存、不动安装内容；
        否则恢复对应快照，first_install 表示当时是首次安装，移除即回滚。
        """
        component(asset_instance_id, "asset_instance_id")
        installed = self.root / "installed" / asset_instance_id
        if rollback_ref is None:
            return "noop"
        backup = self.root / "backup" / asset_instance_id / rollback_ref
        if backup.is_dir():
            if installed.exists():
                shutil.rmtree(installed)
            os.replace(backup, installed)
            return "restored"
        if rollback_ref == FIRST_INSTALL and installed.exists():
            shutil.rmtree(installed)
            return "removed"
        return "noop"

    def discard_staging(self, transaction_id: str) -> None:
        component(transaction_id, "transaction_id")
        staging = self.root / "staging" / transaction_id
        if staging.exists():
            shutil.rmtree(staging)
