"""共享的路径/网络边界判定规则。

由 DataFlowService 与 EffectDiffService 共用，避免敏感文件标记、可信域名
白名单与路径归一规则散落多处。
"""

from __future__ import annotations

import ipaddress
import re

HOME_PREFIX = re.compile(r"^/(?:home|Users)/[^/]+")

SENSITIVE_MARKERS = (
    # 目录级路径（~/.ssh）也要算：列一遍目录同样能看出有哪些密钥。
    ".ssh", "id_rsa", "id_ed25519", "id_ecdsa",
    ".aws/credentials", ".git-credentials", ".npmrc", ".pypirc",
    ".kube/config", ".docker/config.json", "keychain", "login data",
    ".env", "credentials", "cookies", "cookie.sqlite", "wallet.dat",
)

TRUSTED_HOSTS = (
    # 代码托管与包管理：日常构建必经，纳入白名单否则每次 push/install 都误报。
    "github.com", "api.github.com", "codeload.github.com", "objects.githubusercontent.com",
    "gitlab.com", "bitbucket.org",
    "pypi.org", "files.pythonhosted.org", "registry.npmjs.org",
    "registry-1.docker.io", "auth.docker.io", "production.cloudflare.docker.com",
    # 云厂商 API 与模型端点。
    "aws.amazon.com", "sts.amazonaws.com", "s3.amazonaws.com",
    "api.anthropic.com", "api.openai.com", "api.stepfun.com",
)

TRUSTED_SUFFIXES = (".internal", ".local", ".localdomain", ".cluster.local")


def normalize_hint_path(path: str | None) -> str | None:
    """把路径归一成与端侧 resource_hints 同一形态；非路径返回 None。"""
    if not path:
        return None
    return HOME_PREFIX.sub("~", str(path).rstrip("/.,;:"))


def is_sensitive_path(path: str | None) -> bool:
    """判断路径是否触及敏感凭据/配置；公钥 (.pub) 不算敏感源。"""
    if not path:
        return False
    lowered = str(path).lower()
    if lowered.endswith(".pub"):
        return False
    return any(marker in lowered for marker in SENSITIVE_MARKERS)


def is_external_host(host: str | None) -> bool:
    """判断连接目标是否在外部公网。宁可保守，不放过未登记域名与公网 IP。"""
    if not host:
        return False
    value = str(host).strip().lower()
    if value in ("localhost", "::1") or value.startswith("127."):
        return False
    if any(value.endswith(suffix) for suffix in TRUSTED_SUFFIXES):
        return False
    if value in TRUSTED_HOSTS:
        return False
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return True
    return address.is_global
