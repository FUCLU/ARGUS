from __future__ import annotations

import os
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = ROOT / "configs" / "llm.yaml"
PROVIDERS = ("openrouter", "deepseek", "openai-compatible")


@dataclass(frozen=True)
class LLMConfig:
    provider: str = "openrouter"
    model: str = "qwen/qwen3-32b"
    base_url: str = "https://openrouter.ai/api/v1"
    api_key_env: str = "OPENROUTER_API_KEY"
    temperature: float = 0
    max_tokens: int = 4096
    thinking: bool | None = True
    timeout_seconds: float = 180
    max_attempts: int = 3
    fetch_generation_metadata: bool = False

    def __post_init__(self) -> None:
        if self.provider not in PROVIDERS:
            raise ValueError(f"llm.provider must be one of {PROVIDERS}, got {self.provider!r}")
        if not self.model.strip():
            raise ValueError("llm.model must be a non-empty string")
        if not self.base_url.strip():
            raise ValueError("llm.base_url must be a non-empty string")
        if self.max_attempts < 1 or self.max_tokens < 1 or self.timeout_seconds <= 0:
            raise ValueError("llm.max_attempts, max_tokens and timeout_seconds must be positive")

    @property
    def api_key(self) -> str:
        return os.getenv(self.api_key_env, "").strip()


def load_llm_config(path: str | Path | None = None, **overrides: Any) -> LLMConfig:
    """Read the YAML config; non-None keyword overrides (e.g. CLI flags) win."""
    source = Path(path) if path else DEFAULT_CONFIG_PATH
    if not source.is_file():
        raise FileNotFoundError(source)
    data = yaml.safe_load(source.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{source}: expected a mapping")
    known = {field.name for field in fields(LLMConfig)}
    unknown = sorted(set(data) - known)
    if unknown:
        raise ValueError(f"{source}: unknown llm settings {unknown}")
    data.update({key: value for key, value in overrides.items() if value is not None})
    return LLMConfig(**data)
