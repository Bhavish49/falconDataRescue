"""
Application configuration via pydantic-settings.

Reads from environment variables / .env file.
"""

from pathlib import Path
from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Global application settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── App ──────────────────────────────────────────────────────────────
    app_name: str = "falconDataRescue Forensic Recovery"
    app_env: str = "development"
    debug: bool = True
    secret_key: str = "change-me"

    # ── Database ─────────────────────────────────────────────────────────
    # SQLite keeps a fresh checkout runnable without requiring a local
    # PostgreSQL server. Production deployments should override both values
    # with PostgreSQL URLs through the environment.
    database_url: str = "sqlite+aiosqlite:///./mce_forensics.db"
    sync_database_url: str = "sqlite:///./mce_forensics.db"

    # ── Redis ────────────────────────────────────────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    # ── Storage ──────────────────────────────────────────────────────────
    evidence_mount_path: str = "/evidence"
    recovery_output_path: str = "/output"
    max_upload_size_mb: int = 10240

    # ── ML ───────────────────────────────────────────────────────────────
    ml_model_path: str = "/models"
    embedding_model: str = "all-MiniLM-L6-v2"
    embedding_dimension: int = 384
    ai_visual_enabled: bool = True
    ai_visual_model: str = "facebook/dinov2-small"
    ai_allow_model_download: bool = False
    ai_reference_dir: str = ""

    # ── LLM / AI Providers ───────────────────────────────────────────────
    openai_api_key: str = ""
    openai_model: str = "gpt-4o"
    huggingface_api_key: str = ""
    hf_model: str = "meta-llama/Llama-3.1-8B-Instruct"
    llm_max_tokens: int = 4096
    llm_temperature: float = 0.1

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def evidence_path(self) -> Path:
        return Path(self.evidence_mount_path)

    @property
    def output_path(self) -> Path:
        return Path(self.recovery_output_path)


@lru_cache
def get_settings() -> Settings:
    """Cached settings singleton."""
    return Settings()
