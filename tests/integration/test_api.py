"""Integration tests for API endpoints."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from agent.config import Settings
from agent.event_bus import EventBus
from api.main import create_app
from api.models.database import DatabaseManager


@pytest.fixture
def tmp_db():
    with TemporaryDirectory() as tmpdir:
        yield Path(tmpdir) / "test.db"


@pytest.fixture
def app(tmp_db):
    settings = Settings(db_path=tmp_db, debug=True)
    application = create_app(settings)
    # Manually initialize state that lifespan would set up
    db = DatabaseManager(tmp_db)
    db.initialize()
    application.state.db = db
    application.state.event_bus = EventBus()
    return application


@pytest_asyncio.fixture
async def client(app):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as c:
        yield c


@pytest.mark.asyncio
async def test_health(client):
    resp = await client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.asyncio
async def test_search_empty_db(client):
    resp = await client.get("/api/v1/events/search")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 0
    assert data["events"] == []


@pytest.mark.asyncio
async def test_search_with_seeded_data(client, app):
    db = app.state.db
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO events (timestamp, source, event_type, severity, "
            "source_ip, raw_message, metadata) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                "2026-04-09T12:00:00",
                "auth",
                "ssh_failed",
                "medium",
                "10.0.0.1",
                "Failed password for admin",
                json.dumps({}),
            ),
        )

    resp = await client.get("/api/v1/events/search", params={"severity": "medium"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["events"][0]["source_ip"] == "10.0.0.1"


@pytest.mark.asyncio
async def test_search_full_text_finds_seeded_event(client, app):
    """The fts5 index must stay in sync with events via triggers."""
    db = app.state.db
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO events (timestamp, source, event_type, severity, "
            "source_ip, raw_message, metadata) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                "2026-04-09T12:00:00",
                "dns",
                "dns_query",
                "info",
                "10.0.0.7",
                "query[TXT] deadbeef.tunnel.evil.com from 10.0.0.7",
                json.dumps({"domain": "deadbeef.tunnel.evil.com"}),
            ),
        )

    resp = await client.get("/api/v1/events/search", params={"q": "tunnel"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["events"][0]["source"] == "dns"


@pytest.mark.asyncio
async def test_search_full_text_no_match(client, app):
    db = app.state.db
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO events (timestamp, source, event_type, severity, "
            "raw_message, metadata) VALUES (?, ?, ?, ?, ?, ?)",
            ("2026-04-09T12:00:00", "auth", "ssh_failed", "medium",
             "Failed password for admin", json.dumps({})),
        )

    resp = await client.get("/api/v1/events/search", params={"q": "nonexistentterm"})
    assert resp.status_code == 200
    assert resp.json()["total"] == 0


@pytest.mark.asyncio
async def test_search_malformed_fts_query_returns_400(client):
    """fts5 syntax errors are caller input errors, not 500s."""
    resp = await client.get("/api/v1/events/search", params={"q": '"unbalanced'})
    assert resp.status_code == 400
    assert "search query" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_search_invalid_severity(client):
    resp = await client.get("/api/v1/events/search", params={"severity": "extreme"})
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_get_event_not_found(client):
    resp = await client.get("/api/v1/events/99999")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_get_event_invalid_id(client):
    resp = await client.get("/api/v1/events/abc")
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_alerts_empty(client):
    resp = await client.get("/api/v1/alerts")
    assert resp.status_code == 200
    assert resp.json()["total"] == 0


@pytest.mark.asyncio
async def test_acknowledge_nonexistent_alert(client):
    resp = await client.post("/api/v1/alerts/99999/acknowledge")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_stats_overview(client):
    resp = await client.get("/api/v1/stats/overview")
    assert resp.status_code == 200
    data = resp.json()
    assert "total_events" in data
    assert "open_alerts" in data


@pytest.mark.asyncio
async def test_stats_overview_last_hour_window(client, app):
    """Event timestamps are naive local time in ISO 'T' format, so the
    last-hour cutoff must match both the zone and the format: SQLite's
    datetime('now') is UTC and space-separated, which undercounts on
    non-UTC hosts and string-compares wrongly against 'T' timestamps."""
    from datetime import datetime, timedelta

    now = datetime.now()
    db = app.state.db
    with db.connect() as conn:
        for ts in (now, now - timedelta(hours=3)):
            conn.execute(
                "INSERT INTO events (timestamp, source, event_type, severity, "
                "source_ip, raw_message, metadata) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    ts.isoformat(),
                    "auth",
                    "ssh_failed",
                    "medium",
                    "10.0.0.1",
                    "Failed password for admin",
                    json.dumps({}),
                ),
            )

    resp = await client.get("/api/v1/stats/overview")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_events"] == 2
    assert data["events_last_hour"] == 1  # the 3-hour-old event is excluded


@pytest.mark.asyncio
async def test_stats_heatmap(client):
    resp = await client.get("/api/v1/stats/heatmap")
    assert resp.status_code == 200
    data = resp.json()
    assert data["period_days"] == 7
    assert "buckets" in data
