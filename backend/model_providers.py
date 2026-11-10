"""Model-provider profiles with credentials kept out of API responses/logs."""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
from typing import Any


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


def provider_catalog() -> dict[str, Any]:
    selected = os.environ.get("ASGP_MODEL_PROVIDER", "stepfun").strip().lower()
    stepfun_env_key = os.environ.get("STEPFUN_API_KEY", "")
    stepfun_codex_key = "" if stepfun_env_key else _codex_provider_key("stepfun")
    stepfun_key = stepfun_env_key or stepfun_codex_key
    stepfun_model = os.environ.get("STEPFUN_MODEL", "step-5-preview")
    stepfun_chat_url = _safe_base_url(os.environ.get("STEPFUN_CHAT_BASE_URL", "https://api.stepfun.com/v1"))

    xunfei_env_key = os.environ.get("XUNFEI_API_PASSWORD", "")
    xunfei_codex_key = "" if xunfei_env_key else _codex_provider_key("xunfei")
    xunfei_key = xunfei_env_key or xunfei_codex_key
    xunfei_model = os.environ.get("XUNFEI_MODEL", "")
    xunfei_chat_url = _safe_base_url(os.environ.get("XUNFEI_CHAT_BASE_URL", "")) or _codex_provider("xunfei")["base_url"]

    providers = [
        {
            "id": "stepfun",
            "name": "StepFun",
            "role": "primary",
            "selected": selected == "stepfun",
            "codex_profile": _codex_provider("stepfun"),
            "scanner_profile": {
                "wire_api": "chat.completions",
                "base_url": stepfun_chat_url,
                "model": stepfun_model,
                "secret_configured": bool(stepfun_key),
                "credential_source": ("STEPFUN_API_KEY" if stepfun_env_key else
                                      "Codex provider config" if stepfun_codex_key else "not configured"),
                "configured": bool(stepfun_key and stepfun_model and stepfun_chat_url),
            },
        },
        {
            "id": "xunfei",
            "name": "讯飞星火",
            "role": "candidate",
            "selected": selected == "xunfei",
            "codex_profile": _codex_provider("xunfei"),
            "scanner_profile": {
                "wire_api": "chat.completions",
                "base_url": xunfei_chat_url,
                "model": xunfei_model,
                "secret_configured": bool(xunfei_key),
                "credential_source": ("XUNFEI_API_PASSWORD" if xunfei_env_key else
                                      "Codex provider config" if xunfei_codex_key else "not configured"),
                "configured": bool(xunfei_key and xunfei_model and xunfei_chat_url),
            },
        },
    ]
    return {"selected": selected, "providers": providers}


def scanner_provider_environment() -> dict[str, str]:
    """Resolve the selected provider for upstream CLIs using Chat Completions."""
    selected = os.environ.get("ASGP_MODEL_PROVIDER", "stepfun").strip().lower()
    catalog = provider_catalog()
    provider = next((item for item in catalog["providers"] if item["id"] == selected), None)
    if provider is None:
        raise ValueError(f"未知模型供应商：{selected}")
    profile = provider["scanner_profile"]
    if not profile["configured"]:
        if selected == "stepfun":
            raise ValueError("StepFun 主用模型未配置；请设置 STEPFUN_API_KEY。")
        raise ValueError("讯飞星火候选未配置；请设置 XUNFEI_API_PASSWORD、XUNFEI_MODEL 和 XUNFEI_CHAT_BASE_URL。")
    if selected == "stepfun":
        api_key = os.environ.get("STEPFUN_API_KEY") or _codex_provider_key("stepfun")
    else:
        api_key = os.environ.get("XUNFEI_API_PASSWORD") or _codex_provider_key("xunfei")
    return {
        "LLM_API_KEY": api_key,
        "LLM_BASE_URL": profile["base_url"],
        "LLM_MODEL": profile["model"],
    }
