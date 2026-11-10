"""检测器子进程环境与权限收敛。

子进程只拿到运行所需的最小环境变量；密钥只进入指定子进程环境，不进入
API 响应、argv、SQLite 或日志。以 root 运行时可按配置降权到非特权用户，
对应的 HOME/TMPDIR 会一并改归属，避免降权后无法写临时目录。
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

DEFAULT_PATH = "/usr/local/bin:/usr/bin:/bin"

# 代理与 CA 配置按需透传；其余环境一律不继承。
PASSTHROUGH_ENV = (
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
    "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE",
)

# 环境变量名里含这些片段的才按密钥脱敏；base_url、model 之类要留在错误详情里。
SECRET_NAME_MARKERS = ("KEY", "TOKEN", "PASSWORD", "SECRET")


def demotion_user() -> str | None:
    """返回配置的降权用户名；未配置或当前不是 root 时返回 None。"""
    if os.geteuid() != 0:
        return None
    configured = os.environ.get("FUSION_DROP_PRIVILEGES", "").strip()
    return configured or None


def _ids_for(user: str) -> tuple[int, int] | None:
    try:
        import pwd
    except ImportError:
        return None
    try:
        record = pwd.getpwnam(user)
    except KeyError:
        return None
    return record.pw_uid, record.pw_gid


def _drop(cache: dict[str, Any]):
    def apply() -> None:
        user = cache.get("user")
        uid, gid = cache["ids"]
        os.setgid(gid)
        os.setgroups([gid])
        os.setuid(uid)
        cache["applied"] = True

    return apply


def minimal_environment(detector_id: str, *, workdir: Path, extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {
        "PATH": os.environ.get("PATH", DEFAULT_PATH),
        "HOME": str(workdir),
        "TMPDIR": str(workdir),
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONUNBUFFERED": "1",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }
    for name in PASSTHROUGH_ENV:
        value = os.environ.get(name)
        if value:
            env[name] = value
    if detector_id == "snyk-agent-scan" and os.environ.get("SNYK_TOKEN"):
        env["SNYK_TOKEN"] = os.environ["SNYK_TOKEN"]
    # extra 由适配器的 secret_env 声明；适配器是"这个子进程需要什么"的唯一权威。
    if extra:
        env.update(extra)
    return env


def resolve_binary(detector_id: str, binary: str) -> str | None:
    """解析可执行文件并返回绝对路径。

    子进程会切换到独立 cwd，相对路径会在那里失效，所以必须在这里定型。
    """
    override = os.environ.get(f"FUSION_BIN_{detector_id.upper().replace('-', '_')}")
    for candidate in (override, shutil.which(binary)):
        if candidate and Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return str(Path(candidate).resolve())
    return None


def prepare_workdir(base: Path, detector_id: str, demote_to: str | None) -> Path:
    """建好子进程 HOME/TMPDIR；降权时把归属交给目标用户。"""
    workdir = base / "engine-home" / detector_id
    workdir.mkdir(parents=True, exist_ok=True)
    if demote_to:
        ids = _ids_for(demote_to)
        if ids is None:
            raise RuntimeError(f"降权用户 {demote_to} 不存在，拒绝以 root 运行检测器。")
        uid, gid = ids
        os.chown(workdir, uid, gid)
    return workdir


def preexec_for(demote_to: str | None):
    if not demote_to:
        return None
    ids = _ids_for(demote_to)
    if ids is None:
        raise RuntimeError(f"降权用户 {demote_to} 不存在，拒绝以 root 运行检测器。")
    cache = {"user": demote_to, "ids": ids, "applied": False}
    return _drop(cache)
