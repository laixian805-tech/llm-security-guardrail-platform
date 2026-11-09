from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    service_name: str = "llm-security-guardrail-platform"
    assets_root: str = "/home/tlx/llmsec-assets"
    service_base_url: str = "http://127.0.0.1:8000"
    model_provider: str = "stub"
    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "qwen3:8b"
    openai_base_url: str = "http://127.0.0.1:8000/v1"
    openai_api_key: str = "dummy"
    openai_model: str = "qwen3:8b"
    guard_engine: str = "nemo"
    nemo_config_dir: str = ""
    nemo_fallback_engine: str = "custom_nemo"
    nemo_fail_mode: str = "fallback"
    judge_provider: str = "deepseek"
    judge_base_url: str = "https://api.deepseek.com"
    judge_model: str = "deepseek-v4-pro"
    judge_api_key: str = ""
    judge_timeout_seconds: int = 60
    garak_timeout_seconds: int = 900
    chroma_persist_directory: str = "/home/tlx/llmsec-assets/chroma"
    reports_dir: str = "/home/tlx/llmsec-assets/reports"
    # Agent security gateway (docs/agent-security-platform-retrofit-plan.md)
    agentsec_db_path: str = ""
    agentsec_upload_url: str = "http://127.0.0.1:8000/api/agent-security/events"
    agentsec_upload_key: str = ""
    agentsec_enroll_key: str = ""
    agentsec_redact: bool = True
    agentsec_ti_mode: str = "off"
    agentsec_ti_daily_budget: int = 250
    agentsec_ti_hard_daily_limit: int = 300
    agentsec_ti_cache_days: int = 7
    agentsec_ti_timeout_seconds: float = 2.0
    agentsec_heartbeat_seconds: int = 60

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="LLMSEC_",
        extra="ignore",
    )


def get_settings() -> Settings:
    return Settings()


def resolved_agentsec_db_path(settings: Settings) -> str:
    """Platform-side agentsec DB; defaults under assets_root."""
    return settings.agentsec_db_path or f"{settings.assets_root}/agentsec/agentsec.db"
