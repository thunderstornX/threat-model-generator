"""Shared fixtures."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO))

from config import Settings  # noqa: E402


@pytest.fixture
def benchmarks_dir() -> Path:
    return _REPO / "eval" / "benchmarks"


@pytest.fixture
def settings_no_keys(monkeypatch) -> Settings:
    for var in ("ANTHROPIC_API_KEY", "ANTHROPIC_MODEL",
                  "OLLAMA_BASE_URL", "OLLAMA_MODEL"):
        monkeypatch.delenv(var, raising=False)
    return Settings(
        anthropic_api_key=None,
        anthropic_model="claude-haiku-4-5-20251001",
        anthropic_base_url="https://api.anthropic.test/v1/messages",
        ollama_base_url="http://127.0.0.1:65535",
        ollama_model="llama3.2:1b",
        augment_timeout_s=2.0,
    )


@pytest.fixture
def settings_anthropic() -> Settings:
    return Settings(
        anthropic_api_key="sk-test",
        anthropic_model="claude-haiku-4-5-20251001",
        anthropic_base_url="https://api.anthropic.test/v1/messages",
        ollama_base_url="http://127.0.0.1:65535",
        ollama_model="llama3.2:1b",
        augment_timeout_s=2.0,
    )


@pytest.fixture
def settings_ollama() -> Settings:
    return Settings(
        anthropic_api_key=None,
        ollama_base_url="http://127.0.0.1:11434",
        ollama_model="llama3.2:1b",
        augment_timeout_s=2.0,
    )
