"""Shared fixtures for the security test suite.

Builds a fully wired app (auth + rate-limit middleware) over a throwaway
SQLite database, mirroring the ASGITransport pattern used by the integration
tests. Auth-enabled and auth-disabled apps are produced from the same factory
so each test declares exactly the security posture it exercises.
"""

from __future__ import annotations

import time
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from tempfile import TemporaryDirectory

import jwt
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from agent.config import Settings
from agent.event_bus import EventBus
from api.main import create_app
from api.middleware.auth import issue_token
from api.models.database import DatabaseManager

# 32+ byte secret keeps PyJWT's InsecureKeyLengthWarning quiet.
TEST_SECRET = "a-test-secret-that-is-long-enough-32b"  # noqa: S105 (test fixture, not a real credential)


@pytest.fixture
def tmp_db() -> Iterator[Path]:
    with TemporaryDirectory() as tmpdir:
        yield Path(tmpdir) / "test.db"


def _build_app(settings: Settings) -> object:
    application = create_app(settings)
    db = DatabaseManager(settings.db_path)
    db.initialize()
    application.state.db = db
    application.state.event_bus = EventBus()
    return application


@pytest.fixture
def auth_settings(tmp_db: Path) -> Settings:
    """Auth enabled, rate limiting effectively off (high ceiling)."""
    return Settings(
        db_path=tmp_db,
        debug=True,
        jwt_secret=TEST_SECRET,
        rate_limit_per_minute=10_000,
    )


@pytest.fixture
def open_settings(tmp_db: Path) -> Settings:
    """Auth disabled (no secret), rate limiting off."""
    return Settings(db_path=tmp_db, debug=True, jwt_secret="", rate_limit_per_minute=0)


@pytest.fixture
def auth_app(auth_settings: Settings) -> object:
    return _build_app(auth_settings)


@pytest.fixture
def open_app(open_settings: Settings) -> object:
    return _build_app(open_settings)


@pytest_asyncio.fixture
async def auth_client(auth_app: object) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=auth_app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest_asyncio.fixture
async def open_client(open_app: object) -> AsyncIterator[AsyncClient]:
    transport = ASGITransport(app=open_app)  # type: ignore[arg-type]
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


def read_token() -> str:
    return issue_token(TEST_SECRET, "read")


def admin_token() -> str:
    return issue_token(TEST_SECRET, "admin")


def expired_token(scope: str = "read") -> str:
    """A token whose exp is already in the past."""
    past = int(time.time()) - 3600
    return issue_token(TEST_SECRET, scope, issued_at=past, expiry_minutes=1)


def wrong_signature_token(scope: str = "read") -> str:
    """A token signed with a different secret."""
    now = int(time.time())
    return jwt.encode(
        {"scope": scope, "iat": now, "exp": now + 3600},
        "a-completely-different-secret-key-32by",
        algorithm="HS256",
    )


def no_scope_token() -> str:
    """A validly signed token that lacks a scope claim."""
    now = int(time.time())
    return jwt.encode({"iat": now, "exp": now + 3600}, TEST_SECRET, algorithm="HS256")


def bearer(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}
