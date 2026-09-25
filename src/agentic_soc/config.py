"""Runtime configuration, loaded from environment variables or a .env file.

Every setting is prefixed AGENTIC_SOC_. Secrets never live in code.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AGENTIC_SOC_",
        env_file=".env",
        extra="ignore",
    )

    hmac_secret: str = "change-me"
    min_rule_level: int = 9

    anthropic_api_key: str = ""
    model: str = "claude-haiku-4-5"
    max_tokens: int = 2048

    indexer_url: str = ""
    indexer_user: str = "admin"
    indexer_password: str = ""
    indexer_verify_tls: bool = False

    context_path: str = "context/infrastructure.yaml"


def get_settings() -> Settings:
    return Settings()
