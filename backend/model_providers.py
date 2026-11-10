"""Model-provider profiles with credentials kept out of API responses/logs.

同一个供应商有两条互不合并的传输 profile：Codex 用的 Responses profile
和扫描器 CLI 用的 Chat Completions profile。endpoint、wire API 和模型都
可能不同，Probe 也必须分别做——通过一条不代表另一条可用。

密钥只在进程内从环境变量或 Codex 配置头解析，不落库、不进日志、不进
子进程 argv，也不通过 API 回传。
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit, urlunsplit

from domain import ProbeStatus

PROFILE_KINDS = ("codex", "scanner")

# (provider_id, profile_kind) → ProbeStatus，或等价的查询函数。
ProbeStatusSource = Mapping[tuple[str, str], str] | Callable[[str, str], str]

# candidate 进入默认路由前必须通过的 Probe 状态。
ROUTABLE_PROBE_STATUS = "passed"


def _safe_base_url(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        return ""
    parts = urlsplit(value.strip())
    if not parts.scheme or not parts.netloc:
        return ""
    host = parts.netloc.rsplit("@", 1)[-1]
    return urlunsplit((parts.scheme, host, parts.path.rstrip("/"), "", ""))


def _codex_provider(provider_id: str) -> dict[str, str]:
    configured_path = os.environ.get("CODEX_CONFIG_PATH") or str(Path.home() / ".codex" / "config.toml")
    config_path = Path(configured_path)
    try:
        config = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return {"base_url": "", "wire_api": "", "source": "not_found"}
    providers = config.get("model_providers", {})
    provider = providers.get(provider_id, {}) if isinstance(providers, dict) else {}
    if not isinstance(provider, dict):
        provider = {}
    headers = provider.get("http_headers") or {}
    authorization = headers.get("Authorization") or headers.get("authorization") if isinstance(headers, dict) else ""
    return {
        "base_url": _safe_base_url(provider.get("base_url")),
        "wire_api": str(provider.get("wire_api") or ""),
        "source": "codex_config" if provider else "not_found",
        "credential_configured": str(authorization).lower().startswith("bearer "),
    }


def _codex_provider_key(provider_id: str) -> str:
    """Read a provider-specific Bearer key in memory; never return it via API."""
    config_path = Path(os.environ.get("CODEX_CONFIG_PATH") or Path.home() / ".codex" / "config.toml")
    try:
        config = tomllib.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return ""
    providers = config.get("model_providers", {})
    provider = providers.get(provider_id, {}) if isinstance(providers, dict) else {}
    if not isinstance(provider, dict):
        return ""
    headers = provider.get("http_headers") or {}
    authorization = headers.get("Authorization") or headers.get("authorization") if isinstance(headers, dict) else ""
    if not isinstance(authorization, str):
        return ""
    scheme, separator, value = authorization.partition(" ")
    if separator and scheme.lower() == "bearer":
        return value.strip()
    return ""


def _scanner_key(provider_id: str) -> tuple[str, str]:
    """返回 (key, 来源)。环境变量优先，其次 Codex 配置头。"""
    env_names = {
        "stepfun": ("STEPFUN_API_KEY", "STEPFUN_API_KEY"),
        "xunfei": ("XUNFEI_API_PASSWORD", "XUNFEI_API_PASSWORD"),
    }
    env_name = env_names.get(provider_id, ("", ""))[0]
    if env_name:
        value = os.environ.get(env_name, "")
        if value:
            return value, env_name
    codex_key = _codex_provider_key(provider_id)
    if codex_key:
        return codex_key, "Codex provider config"
    return "", "not configured"


def _scanner_profile(provider_id: str) -> dict[str, Any]:
    """扫描器 CLI 侧的 Chat Completions profile，含进程内密钥。"""
    key, key_source = _scanner_key(provider_id)
    if provider_id == "xunfei":
        model = os.environ.get("XUNFEI_MODEL", "")
        base_url = _safe_base_url(os.environ.get("XUNFEI_CHAT_BASE_URL", "")) or _codex_provider("xunfei")["base_url"]
        missing = "讯飞星火候选未配置；请设置 XUNFEI_API_PASSWORD、XUNFEI_MODEL 和 XUNFEI_CHAT_BASE_URL。"
    else:
        model = os.environ.get("STEPFUN_MODEL", "step-5-preview")
        base_url = _safe_base_url(os.environ.get("STEPFUN_CHAT_BASE_URL", "https://api.stepfun.com/v1"))
        missing = "StepFun 主用模型未配置；请设置 STEPFUN_API_KEY。"
    return {
        "provider_id": provider_id,
        "profile_kind": "scanner",
        "wire_api": "chat_completions",
        "base_url": base_url,
        "model": model,
        "api_key": key,
        "credential_source": key_source,
        "configured": bool(key and model and base_url),
        "missing_hint": missing,
    }


def _codex_profile(provider_id: str) -> dict[str, Any]:
    """Codex 侧的 Responses profile，含进程内密钥。

    模型不从 Codex 顶层配置推断：那个 model 属于当前 model_provider，换一
    家就未必存在，拿它 Probe 只会得到假的 404。必须由
    {PROVIDER}_CODEX_MODEL 显式指定。
    """
    meta = _codex_provider(provider_id)
    key = _codex_provider_key(provider_id)
    model = os.environ.get(f"{provider_id.upper()}_CODEX_MODEL", "")
    return {
        "provider_id": provider_id,
        "profile_kind": "codex",
        "wire_api": meta["wire_api"],
        "base_url": meta["base_url"],
        "model": model,
        "api_key": key,
        "credential_source": meta["source"],
        "configured": bool(key and meta["base_url"] and model),
        "missing_hint": (
            f"{provider_id} 的 Codex profile 未配置；需要 Codex 配置里的 base_url、"
            "http_headers，以及用环境变量显式指定模型。"
        ),
    }


def resolve_wire_profile(provider_id: str, profile_kind: str) -> dict[str, Any]:
    """解析一条传输 profile。api_key 只在本进程内流转，调用方不得外泄。"""
    if profile_kind not in PROFILE_KINDS:
        raise ValueError(f"未知的 profile 类型：{profile_kind}")
    resolver = _scanner_profile if profile_kind == "scanner" else _codex_profile
    return resolver(provider_id)


def selected_provider_id() -> str:
    return os.environ.get("ASGP_MODEL_PROVIDER", "stepfun").strip().lower()


def _probe_status(probe_status: ProbeStatusSource | None,
                  provider_id: str, profile_kind: str) -> str:
    """取最近一次 Probe 状态。

    probe_status 可以是 (provider_id, profile_kind) → status 的映射，也可以
    是 status_for(provider_id, profile_kind) 这样的查询函数——适配器手里只
    有函数，控制面组装清单时用映射，两种都要认。
    """
    if probe_status is None:
        return ProbeStatus.UNKNOWN.value
    if callable(probe_status):
        return str(probe_status(provider_id, profile_kind) or ProbeStatus.UNKNOWN.value)
    return probe_status.get((provider_id, profile_kind), ProbeStatus.UNKNOWN.value)


def provider_catalog(probe_status: ProbeStatusSource | None = None) -> dict[str, Any]:
    selected = selected_provider_id()
    stepfun_codex = _codex_provider("stepfun")
    xunfei_codex = _codex_provider("xunfei")
    stepfun_scanner = _scanner_profile("stepfun")
    xunfei_scanner = _scanner_profile("xunfei")

    def entry(provider_id: str, name: str, role: str, codex: dict[str, Any],
              scanner: dict[str, Any]) -> dict[str, Any]:
        scanner_probe = _probe_status(probe_status, provider_id, "scanner")
        # Probe 失败的 provider 不进入默认路由，不论主用还是候选；候选还
        # 额外要求已经通过（未 Probe 的候选同样不可路由）。
        routable = scanner_probe != "failed" and (
            role != "candidate" or scanner_probe == ROUTABLE_PROBE_STATUS
        )
        return {
            "id": provider_id,
            "name": name,
            "role": role,
            "selected": selected == provider_id,
            "routable": routable,
            "codex_profile": {
                "base_url": codex["base_url"],
                "wire_api": codex["wire_api"],
                "source": codex["source"],
                "credential_configured": codex["credential_configured"],
            },
            "scanner_profile": {
                "wire_api": "chat.completions",
                "base_url": scanner["base_url"],
                "model": scanner["model"],
                "secret_configured": scanner["configured"],
                "credential_source": scanner["credential_source"],
                "configured": scanner["configured"],
            },
            "probe": {
                "scanner": scanner_probe,
                "codex": _probe_status(probe_status, provider_id, "codex"),
            },
        }

    providers = [
        entry("stepfun", "StepFun", "primary", stepfun_codex, stepfun_scanner),
        entry("xunfei", "讯飞星火", "candidate", xunfei_codex, xunfei_scanner),
    ]
    return {"selected": selected, "providers": providers}


def routing_decision(probe_status: ProbeStatusSource | None = None) -> dict[str, Any]:
    """选出扫描器实际使用的 profile。

    candidate 未通过 Probe 时拒绝路由，不静默回落到主用——那会把配置错误
    藏起来，让人以为候选已经可用。
    """
    selected = selected_provider_id()
    catalog = provider_catalog(probe_status)
    provider = next((item for item in catalog["providers"] if item["id"] == selected), None)
    if provider is None:
        raise ValueError(f"未知模型供应商：{selected}")
    if not provider["routable"]:
        raise ValueError(
            f"供应商 {selected} 最近一次 Probe 未通过，不进入默认路由；"
            "请先执行 Probe 或把 ASGP_MODEL_PROVIDER 切到可用的供应商。"
        )
    return provider


def scanner_provider_environment(
    probe_status: ProbeStatusSource | None = None,
) -> dict[str, str]:
    """Resolve the selected provider for upstream CLIs using Chat Completions."""
    provider = routing_decision(probe_status)
    profile = resolve_wire_profile(provider["id"], "scanner")
    if not profile["configured"]:
        raise ValueError(profile["missing_hint"])
    return {
        "LLM_API_KEY": profile["api_key"],
        "LLM_BASE_URL": profile["base_url"],
        "LLM_MODEL": profile["model"],
    }
