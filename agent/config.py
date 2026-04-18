"""Application configuration with environment variable overrides."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

__all__ = ["Settings", "get_settings"]

_BASE_DIR = Path(__file__).resolve().parent.parent


@dataclass(frozen=True, slots=True)
class Settings:
    """Immutable application settings.

    Values are read from environment variables at startup, falling back to
    sensible defaults for local development. No .env file is loaded
    automatically — use your shell profile or a process manager.
    """

    # Server
    host: str = "127.0.0.1"
    port: int = 8000
    debug: bool = False
    demo_mode: bool = False

    # Database
    db_path: Path = _BASE_DIR / "data" / "threatscope.db"

    # Security
    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    jwt_expiry_minutes: int = 60
    cors_origins: list[str] = field(default_factory=lambda: ["http://localhost:5173"])
    rate_limit_per_minute: int = 60

    # Log collection
    log_sources: list[Path] = field(default_factory=lambda: [
        Path("/var/log/auth.log"),
        Path("/var/log/syslog"),
    ])

    # ML
    anomaly_threshold: float = 0.7
    baseline_window_days: int = 30

    # Threat narration
    narration_api_key: str = ""
    narration_cache_ttl: int = 300


def get_settings() -> Settings:
    """Build settings from environment variables."""
    return Settings(
        host=os.getenv("THREATSCOPE_HOST", "127.0.0.1"),
        port=int(os.getenv("THREATSCOPE_PORT", "8000")),
        debug=os.getenv("THREATSCOPE_DEBUG", "").lower() in ("1", "true"),
        demo_mode=os.getenv("THREATSCOPE_DEMO", "").lower() in ("1", "true"),
        db_path=Path(os.getenv("THREATSCOPE_DB_PATH", str(_BASE_DIR / "data" / "threatscope.db"))),
        jwt_secret=os.getenv("THREATSCOPE_JWT_SECRET", ""),
        cors_origins=os.getenv("THREATSCOPE_CORS_ORIGINS", "http://localhost:5173").split(","),
        rate_limit_per_minute=int(os.getenv("THREATSCOPE_RATE_LIMIT", "60")),
        narration_api_key=os.getenv("THREATSCOPE_NARRATION_KEY", ""),
    )
