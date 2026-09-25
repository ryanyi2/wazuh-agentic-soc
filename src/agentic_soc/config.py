"""Runtime configuration, loaded from environment variables or a .env file.

Every setting is prefixed AGENTIC_SOC_ (e.g. AGENTIC_SOC_HMAC_SECRET). Secrets
never live in code, so the same image runs in dev and prod with different env.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AGENTIC_SOC_",
        env_file=".env",
        extra="ignore",
    )

    # Shared secret the Wazuh hook uses to sign alert payloads (HMAC-SHA256).
    hmac_secret: str = "change-me"
    # Minimum Wazuh rule level this service will analyze.
    min_rule_level: int = 9


def get_settings() -> Settings:
    return Settings()
