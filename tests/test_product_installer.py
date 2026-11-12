"""产品加载路径安装器：落真实技能目录、会话级验证与降级标注。

核心判据：文件级通过不等于产品已加载。loaded 为 None 只能读作"未验证"，
任何测试都不允许把它当成已生效。
"""
from pathlib import Path

import pytest

from services import product_installer as pi
from services.governance_service import GovernanceService
from services.managed_installer import FIRST_INSTALL, InstallerError, ManagedInstaller, tree_hash
from services.product_installer import ProductBinding, ProductInstaller, parse_bindings
from storage.repositories import Storage


def make_skill(root: Path, name: str = "demo", body: str = "# Demo\n") -> Path:
    package = root / name
    package.mkdir(parents=True, exist_ok=True)
    (package / "SKILL.md").write_text(body, encoding="utf-8")
    return package


@pytest.fixture
def home(tmp_path):
    directory = tmp_path / "home"
    directory.mkdir()
    return directory


@pytest.fixture
def installer(tmp_path, home):
    return ProductInstaller(
        [ProductBinding("claude-code", str(home))],
        backup_root=tmp_path / "backup",
    )


class _Completed:
    def __init__(self, stdout: str, returncode: int = 0):
        self.stdout, self.stderr, self.returncode = stdout, "", returncode


def test_install_lands_in_real_product_skill_directory(installer, tmp_path, home):
    staging = make_skill(tmp_path / "staging")
    digest = tree_hash(staging)
    result = installer.install("claude-code", "demo", staging, digest)
    assert Path(result["target"]) == home / ".claude/skills/demo"
    assert (home / ".claude/skills/demo/SKILL.md").is_file()
    assert result["observed_hash"] == digest
    assert result["rollback_ref"] == FIRST_INSTALL


def test_hash_mismatch_rejected_before_any_write(installer, tmp_path, home):
    staging = make_skill(tmp_path / "staging")
    with pytest.raises(InstallerError) as exc:
        installer.install("claude-code", "demo", staging, "0" * 64)
    assert exc.value.code == "content_drift"
    assert not (home / ".claude/skills/demo").exists()


def test_symlinked_target_is_refused(installer, tmp_path, home):
    root = home / ".claude/skills"
    root.mkdir(parents=True)
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "demo").symlink_to(outside, target_is_directory=True)
    staging = make_skill(tmp_path / "staging")
    with pytest.raises(InstallerError) as exc:
        installer.install("claude-code", "demo", staging, tree_hash(staging))
    assert exc.value.code == "installer_symlink_forbidden"
    assert not any(outside.iterdir())


def test_directory_name_must_be_single_safe_component(installer, tmp_path):
    staging = make_skill(tmp_path / "staging")
    for bad in ["..", "a/b", "a\\b", "", "-lead"]:
        with pytest.raises(InstallerError):
            installer.install("claude-code", bad, staging, tree_hash(staging))


def test_unbound_product_is_rejected(installer, tmp_path):
    staging = make_skill(tmp_path / "staging")
    with pytest.raises(InstallerError) as exc:
        installer.install("cursor", "demo", staging, tree_hash(staging))
    assert exc.value.code == "unknown_product" and exc.value.status == 400


def test_upgrade_snapshots_previous_version_and_rollback_restores(installer, tmp_path, home):
    v1 = make_skill(tmp_path / "v1", body="# v1\n")
    installer.install("claude-code", "demo", v1, tree_hash(v1))
    v2 = make_skill(tmp_path / "v2", body="# v2\n")
    result = installer.install("claude-code", "demo", v2, tree_hash(v2))
    assert result["rollback_ref"] != FIRST_INSTALL
    manifest = home / ".claude/skills/demo/SKILL.md"
    assert "v2" in manifest.read_text(encoding="utf-8")
    assert installer.remove("claude-code", "demo", result["rollback_ref"]) == "restored"
    assert "v1" in manifest.read_text(encoding="utf-8")


def test_first_install_rollback_removes_directory(installer, tmp_path, home):
    staging = make_skill(tmp_path / "staging")
    result = installer.install("claude-code", "demo", staging, tree_hash(staging))
    assert installer.remove("claude-code", "demo", result["rollback_ref"]) == "removed"
    assert not (home / ".claude/skills/demo").exists()


def test_verify_without_probe_reports_filesystem_only(installer, tmp_path):
    staging = make_skill(tmp_path / "staging")
    digest = tree_hash(staging)
    installer.install("claude-code", "demo", staging, digest)
    result = installer.verify("claude-code", "demo", digest, probe=False)
    assert result["level"] == "filesystem"
    assert result["loaded"] is None
    assert result["probe"] == "not_requested"


def test_verify_degrades_when_cli_missing(installer, tmp_path, monkeypatch):
    staging = make_skill(tmp_path / "staging")
    digest = tree_hash(staging)
    installer.install("claude-code", "demo", staging, digest)
    monkeypatch.setattr(pi, "_resolve_command", lambda name, home: None)
    result = installer.verify("claude-code", "demo", digest, probe=True)
    assert result["level"] == "filesystem"
    assert result["loaded"] is None
    assert result["probe"] == "cli_not_found"


def test_verify_reports_unsupported_probe_for_unmeasured_product(tmp_path, home):
    installer = ProductInstaller([ProductBinding("codex", str(home))], backup_root=tmp_path / "backup")
    staging = make_skill(tmp_path / "staging")
    digest = tree_hash(staging)
    installer.install("codex", "demo", staging, digest)
    result = installer.verify("codex", "demo", digest, probe=True)
    assert result["probe"] == "unsupported_for_product"
    assert result["loaded"] is None


def test_probe_marks_unrecognized_skill_as_not_loaded(installer, tmp_path, monkeypatch):
    staging = make_skill(tmp_path / "staging")
    digest = tree_hash(staging)
    installer.install("claude-code", "demo", staging, digest)
    monkeypatch.setattr(pi, "_resolve_command", lambda name, home: "/usr/bin/claude")
    monkeypatch.setattr(pi.subprocess, "run", lambda *a, **k: _Completed("Unknown command: /demo"))
    result = installer.verify("claude-code", "demo", digest, probe=True)
    assert result["level"] == "product_session"
    assert result["loaded"] is False


def test_probe_marks_loaded_skill_as_loaded(installer, tmp_path, monkeypatch):
    staging = make_skill(tmp_path / "staging")
    digest = tree_hash(staging)
    installer.install("claude-code", "demo", staging, digest)
    monkeypatch.setattr(pi, "_resolve_command", lambda name, home: "/usr/bin/claude")
    monkeypatch.setattr(pi.subprocess, "run", lambda *a, **k: _Completed("ASGP_PROBE_OK"))
    result = installer.verify("claude-code", "demo", digest, probe=True)
    assert result["loaded"] is True


def test_probe_timeout_is_inconclusive(installer, tmp_path, monkeypatch):
    staging = make_skill(tmp_path / "staging")
    digest = tree_hash(staging)
    installer.install("claude-code", "demo", staging, digest)
    monkeypatch.setattr(pi, "_resolve_command", lambda name, home: "/usr/bin/claude")

    def boom(*args, **kwargs):
        raise pi.subprocess.TimeoutExpired(cmd="claude", timeout=1)

    monkeypatch.setattr(pi.subprocess, "run", boom)
    result = installer.verify("claude-code", "demo", digest, probe=True)
    # 超时只说明没得出结论，不能当"产品否认该技能"。
    assert result["loaded"] is None
    assert result["probe"]["outcome"] == "timeout"


def test_probe_nonzero_without_denial_is_inconclusive(installer, tmp_path, monkeypatch):
    staging = make_skill(tmp_path / "staging")
    digest = tree_hash(staging)
    installer.install("claude-code", "demo", staging, digest)
    monkeypatch.setattr(pi, "_resolve_command", lambda name, home: "/usr/bin/claude")
    monkeypatch.setattr(pi.subprocess, "run",
                        lambda *a, **k: _Completed("Invalid API key · Please run /login", returncode=1))
    result = installer.verify("claude-code", "demo", digest, probe=True)
    assert result["loaded"] is None and result["probe"]["outcome"] == "inconclusive"


def test_verify_requires_manifest(installer, tmp_path, home):
    staging = tmp_path / "staging"
    staging.mkdir()
    (staging / "notes.txt").write_text("x", encoding="utf-8")
    digest = tree_hash(staging)
    installer.install("claude-code", "demo", staging, digest)
    with pytest.raises(InstallerError) as exc:
        installer.verify("claude-code", "demo", digest, probe=False)
    assert exc.value.code == "product_manifest_missing"


def test_parse_bindings_rejects_malformed_config():
    assert parse_bindings(None) == []
    assert parse_bindings("  ") == []
    for bad in ("{not json", '{"product_id":"x"}', "[]extra"):
        with pytest.raises(ValueError):
            parse_bindings(bad)
    parsed = parse_bindings('[{"product_id":"claude-code","home":"/home/u","owner":"u"}]')
    assert parsed[0].owner == "u" and parsed[0].product_id == "claude-code"


def test_admission_commit_writes_product_directory_and_verify_marks_unverified(tmp_path, home, monkeypatch):
    """端到端：准入 commit 必须产生产品目录；探测不可用时 verify 不得声称已加载。"""
    storage = Storage(tmp_path / "fusion.db")
    installer = ManagedInstaller(tmp_path / "managed")
    products = ProductInstaller([ProductBinding("claude-code", str(home))], backup_root=tmp_path / "backup")
    service = GovernanceService(storage, installer=installer, products=products)
    # 控制面机器通常没有产品 CLI；固定这个前提下再断言等级。
    monkeypatch.setattr(pi, "_resolve_command", lambda name, home: None)

    package = installer.root / "inbound" / "demo"
    package.mkdir(parents=True)
    (package / "SKILL.md").write_text("# demo\n", encoding="utf-8")
    digest = tree_hash(package)

    admission = service.check_admission({
        "asset_instance_id": "inst_demo",
        "content_hash": digest,
        "transaction_id": "txn_demo",
        "product_id": "claude-code",
    })
    assert admission.product_id == "claude-code"
    service.admission_transition(admission.admission_id, "approve", {}, "tester")
    service.admission_transition(admission.admission_id, "stage", {"source_path": "demo"}, "tester")
    committed = service.admission_transition(admission.admission_id, "commit", {}, "tester")
    assert (home / ".claude/skills/inst_demo/SKILL.md").is_file()
    assert committed.product_target == str(home / ".claude/skills/inst_demo")
    assert committed.product_loaded is None

    verified = service.admission_transition(admission.admission_id, "verify", {}, "tester")
    assert verified.state.value == "verified"
    # 开发机没有产品 CLI 时会降级：必须标成未验证，不能写成已加载。
    assert verified.product_loaded is None
    assert verified.product_verification == "filesystem:cli_not_found"

    rolled = service.admission_transition(admission.admission_id, "rollback", {}, "tester")
    assert rolled.state.value == "rolled_back"
    assert not (home / ".claude/skills/inst_demo").exists()


def test_admission_verify_fails_when_product_denies_skill(tmp_path, home, monkeypatch):
    """产品明确不认识该技能时，verify 必须失败，不能继续标 verified。"""
    storage = Storage(tmp_path / "fusion.db")
    installer = ManagedInstaller(tmp_path / "managed")
    products = ProductInstaller([ProductBinding("claude-code", str(home))], backup_root=tmp_path / "backup")
    service = GovernanceService(storage, installer=installer, products=products)

    package = installer.root / "inbound" / "demo"
    package.mkdir(parents=True)
    (package / "SKILL.md").write_text("# demo\n", encoding="utf-8")
    digest = tree_hash(package)

    admission = service.check_admission({
        "asset_instance_id": "inst_deny",
        "content_hash": digest,
        "transaction_id": "txn_deny",
        "product_id": "claude-code",
    })
    service.admission_transition(admission.admission_id, "approve", {}, "tester")
    service.admission_transition(admission.admission_id, "stage", {"source_path": "demo"}, "tester")
    service.admission_transition(admission.admission_id, "commit", {}, "tester")

    monkeypatch.setattr(pi, "_resolve_command", lambda name, home: "/usr/bin/claude")
    monkeypatch.setattr(pi.subprocess, "run",
                        lambda *a, **k: _Completed("Unknown command: /inst_deny"))
    result = service.admission_transition(admission.admission_id, "verify", {}, "tester")
    assert result.state.value == "failed"
    assert "product_skill_not_loaded" in result.failure_reason


def test_admission_rejects_unbound_product(tmp_path, home):
    storage = Storage(tmp_path / "fusion.db")
    installer = ManagedInstaller(tmp_path / "managed")
    products = ProductInstaller([ProductBinding("claude-code", str(home))], backup_root=tmp_path / "backup")
    service = GovernanceService(storage, installer=installer, products=products)
    with pytest.raises(Exception) as exc:
        service.check_admission({
            "asset_instance_id": "inst_x",
            "content_hash": "a" * 64,
            "transaction_id": "txn_x",
            "product_id": "qwen-code",
        })
    assert getattr(exc.value, "code", "") == "unknown_product"
