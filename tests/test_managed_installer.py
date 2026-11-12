"""受管安装器：路径封闭、内容哈希与真实 stage/commit/verify/rollback。"""
import os
import stat
from pathlib import Path

import pytest

from services.managed_installer import (
    InstallerError,
    ManagedInstaller,
    component,
    tree_hash,
)


def make_package(installer: ManagedInstaller, name: str, body: str = "print('ok')\n") -> Path:
    package = installer.root / "inbound" / name
    (package / "src").mkdir(parents=True, exist_ok=True)
    (package / "src" / "main.py").write_text(body, encoding="utf-8")
    (package / "README.md").write_text(name, encoding="utf-8")
    return package


@pytest.fixture
def installer(tmp_path):
    return ManagedInstaller(tmp_path / "managed")


def test_component_rejects_traversal_and_separators():
    assert component("asset-1.2_x", "asset_instance_id") == "asset-1.2_x"
    for bad in ["..", ".", "a/b", "", "a\\b", "-lead", "x" * 81, None, 5]:
        with pytest.raises(InstallerError):
            component(bad, "asset_instance_id")


def test_tree_hash_is_deterministic_and_content_addressed(installer, tmp_path):
    first, second = tmp_path / "a", tmp_path / "b"
    for target, body in ((first, "one"), (second, "one")):
        (target / "nested").mkdir(parents=True)
        (target / "nested" / "f.txt").write_text(body, encoding="utf-8")
    assert tree_hash(first) == tree_hash(second)
    (second / "nested" / "f.txt").write_text("two", encoding="utf-8")
    assert tree_hash(first) != tree_hash(second)


def test_tree_hash_refuses_symlink_and_non_regular(tmp_path):
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "real.txt").write_text("x", encoding="utf-8")
    os.symlink("/etc/passwd", package / "link.txt")
    with pytest.raises(InstallerError):
        tree_hash(package)
    os.remove(package / "link.txt")
    os.mkfifo(package / "pipe")
    with pytest.raises(InstallerError):
        tree_hash(package)


def test_stage_confines_source_to_inbound(installer, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "payload.py").write_text("x", encoding="utf-8")
    for bad in ["../outside", "/etc", "outside", "..", ""]:
        with pytest.raises(InstallerError):
            installer.stage("txn_1", bad)


def test_stage_refuses_symlink_and_setuid_sources(installer, tmp_path):
    package = make_package(installer, "pkg")
    os.symlink("/etc/passwd", package / "src" / "leak.py")
    with pytest.raises(InstallerError):
        installer.stage("txn_1", "pkg")
    os.remove(package / "src" / "leak.py")
    target = package / "src" / "main.py"
    target.chmod(target.stat().st_mode | stat.S_ISUID)
    with pytest.raises(InstallerError):
        installer.stage("txn_1", "pkg")


def test_stage_commit_verify_rollback_round_trip(installer, tmp_path):
    package = make_package(installer, "pkg")
    staged_hash = installer.stage("txn_1", "pkg")
    assert staged_hash == tree_hash(installer.root / "inbound" / "pkg")
    committed, rollback_ref = installer.commit("txn_1", "asset_1", staged_hash)
    assert committed == staged_hash and rollback_ref == "first_install"
    assert (installer.root / "installed" / "asset_1" / "src" / "main.py").is_file()
    assert installer.verify("asset_1") == staged_hash
    assert not (installer.root / "staging" / "txn_1").exists()

    # 升级：提交前快照旧版本，回滚后旧内容恢复。
    make_package(installer, "pkg", body="print('v2')\n")
    second_hash = installer.stage("txn_2", "pkg")
    _, second_ref = installer.commit("txn_2", "asset_1", second_hash)
    assert second_hash != staged_hash and second_ref != "first_install"
    assert installer.rollback("asset_1", second_ref) == "restored"
    assert installer.verify("asset_1") == staged_hash

    # 首次安装的回滚没有快照可恢复，移除即回到未安装。
    installer.stage("txn_4", "pkg")
    _, first_ref = installer.commit("txn_4", "asset_2", second_hash)
    assert first_ref == "first_install"
    assert installer.rollback("asset_2", first_ref) == "removed"
    with pytest.raises(InstallerError):
        installer.verify("asset_2")


def test_commit_detects_drift_and_restores_previous_version(installer, tmp_path):
    package = make_package(installer, "pkg")
    staged_hash = installer.stage("txn_1", "pkg")
    installer.commit("txn_1", "asset_1", staged_hash)
    # 审批通过后暂存内容被改写：commit 必须失败且不动已安装版本。
    installer.stage("txn_2", "pkg")
    (installer.root / "staging" / "txn_2" / "src" / "main.py").write_text("tampered", encoding="utf-8")
    with pytest.raises(InstallerError) as excinfo:
        installer.commit("txn_2", "asset_1", staged_hash)
    assert excinfo.value.code == "content_drift"
    assert installer.verify("asset_1") == staged_hash


def test_commit_requires_staging_and_rejects_unknown_actions(installer, tmp_path):
    make_package(installer, "pkg")
    with pytest.raises(InstallerError):
        installer.commit("txn_missing", "asset_1", "a" * 64)
    with pytest.raises(InstallerError):
        installer.verify("asset_missing")


def test_rollback_of_uncommitted_transaction_keeps_installed_content(installer, tmp_path):
    package = make_package(installer, "pkg")
    first, _ = installer.commit("txn_1", "asset_1", installer.stage("txn_1", "pkg"))
    make_package(installer, "pkg", body="print('v2')\n")
    second = installer.stage("txn_2", "pkg")
    assert second != first
    # 未提交事务的回滚凭据为 None：只丢暂存，不动已有安装。
    assert installer.rollback("asset_1", None) == "noop"
    installer.discard_staging("txn_2")
    assert installer.verify("asset_1") == first
    assert not (installer.root / "staging" / "txn_2").exists()
