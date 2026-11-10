"""
ThreatIQ Configuration Management
Loads typed configuration from environment variables with sensible defaults.
"""

from typing import List, Union
from pydantic import AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "ThreatIQ"
    VERSION: str = "0.1.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True
    API_V1_PREFIX: str = "/api/v1"

    # Database Settings
    # Production / Container uses PostgreSQL.
    # Defaults to SQLite async for local zero-dependency testing if postgres not reachable.
    DATABASE_URL: str = "sqlite+aiosqlite:///./threatiq.db"
    SYNC_DATABASE_URL: str = "sqlite:///./threatiq.db"

    # Redis Streaming Settings
    REDIS_URL: str = "redis://localhost:6379/0"

    # Security Settings
    SECRET_KEY: str = "threatiq-insecure-development-secret-key-change-in-prod"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 1 day
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://localhost:8000",
    ]

    # Enforcement of Zero-Destructive Action Rule
    ALLOW_DESTRUCTIVE_ACTIONS: bool = False

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )


settings = Settings()

