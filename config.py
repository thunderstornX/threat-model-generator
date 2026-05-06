"""Settings loaded from environment / .env.

Every external provider is optional. The deterministic rule catalogue
is the *measured* path; LLM augmentation is supported but not
benchmarked, mirroring the honest stance of the companion
ai-governance-checker repo."""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Process configuration. Pulled from env, .env, or constructor args."""

    anthropic_api_key: str | None = None
    anthropic_model: str = "claude-haiku-4-5-20251001"
    anthropic_base_url: str = "https://api.anthropic.com/v1/messages"

    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_model: str = "llama3.2:1b"

    augment_timeout_s: float = 30.0

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )


def load_settings(**overrides) -> Settings:
    """Construct Settings, accepting test-time overrides as kwargs."""
    return Settings(**overrides)
