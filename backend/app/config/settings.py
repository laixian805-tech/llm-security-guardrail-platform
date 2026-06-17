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
    garak_timeout_seconds: int = 900
    chroma_persist_directory: str = "/home/tlx/llmsec-assets/chroma"
    reports_dir: str = "/home/tlx/llmsec-assets/reports"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="LLMSEC_",
        extra="ignore",
    )


def get_settings() -> Settings:
    return Settings()
