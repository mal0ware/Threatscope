"""Tests for per-IP rate limiting."""

from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from agent.config import Settings
from agent.event_bus import EventBus
from api.main import create_app
from api.middleware.ratelimit import FixedWindowRateLimiter
from api.models.database import DatabaseManager

# --- Unit: fixed-window counter -------------------------------------------


def test_limiter_allows_up_to_limit() -> None:
    limiter = FixedWindowRateLimiter(3)
    assert limiter.check("1.2.3.4", now=0.0) == (True, 0)
    assert limiter.check("1.2.3.4", now=0.0) == (True, 0)
    assert limiter.check("1.2.3.4", now=0.0) == (True, 0)


def test_limiter_blocks_over_limit_with_retry_after() -> None:
    limiter = FixedWindowRateLimiter(2)
    limiter.check("1.2.3.4", now=0.0)
    limiter.check("1.2.3.4", now=0.0)
    allowed, retry_after = limiter.check("1.2.3.4", now=10.0)
    assert allowed is False
    # 60s window started at t=0, we're at t=10 -> ~50s remain.
    assert 1 <= retry_after <= 60


def test_limiter_is_per_key() -> None:
    limiter = FixedWindowRateLimiter(1)
    assert limiter.check("a", now=0.0)[0] is True
    assert limiter.check("a", now=0.0)[0] is False
    # Different key has its own budget.
    assert limiter.check("b", now=0.0)[0] is True


def test_limiter_resets_after_window() -> None:
    limiter = FixedWindowRateLimiter(1)
    assert limiter.check("a", now=0.0)[0] is True
    assert limiter.check("a", now=30.0)[0] is False
    # Window fully elapsed -> budget refreshes.
    assert limiter.check("a", now=61.0)[0] is True


# --- Integration: 429 over ASGI transport ---------------------------------


@pytest_asyncio.fixture
async def limited_client():  # type: ignore[no-untyped-def]
    with TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.db"
        # Tiny budget, auth off, so we isolate the rate-limit behavior.
        settings = Settings(
            db_path=db_path, debug=True, jwt_secret="", rate_limit_per_minute=3
        )
        app = create_app(settings)
        db = DatabaseManager(db_path)
        db.initialize()
        app.state.db = db
        app.state.event_bus = EventBus()
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as c:
            yield c


@pytest.mark.asyncio
async def test_rate_limit_triggers_429(limited_client) -> None:  # type: ignore[no-untyped-def]
    # First 3 requests inside the budget succeed; the 4th is throttled.
    for _ in range(3):
        ok = await limited_client.get("/api/v1/stats/overview")
        assert ok.status_code == 200

    blocked = await limited_client.get("/api/v1/stats/overview")
    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers
    assert int(blocked.headers["Retry-After"]) >= 1


@pytest.mark.asyncio
async def test_health_exempt_from_rate_limit(limited_client) -> None:  # type: ignore[no-untyped-def]
    # Health is a liveness probe and must never be throttled.
    for _ in range(10):
        resp = await limited_client.get("/health")
        assert resp.status_code == 200
