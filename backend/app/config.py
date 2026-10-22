"""PENTURION application settings."""
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# backend/app/config.py -> project root is two levels above this file's parent.
PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    app_name: str = "PENTURION API"
    app_version: str = "0.1.0"
    api_v1_prefix: str = "/api/v1"
    database_url: str = f"sqlite:///{(PROJECT_ROOT / 'data' / 'penturion.db').as_posix()}"
    data_dir: Path = PROJECT_ROOT / "data"
    log_level: str = "INFO"
    jwt_secret_key: str
    access_token_expire_minutes: int = 15

    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    """Return one cached settings instance."""
    return Settings()


settings = get_settings()
