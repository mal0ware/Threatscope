"""Integration tests for the event bus -> SQLite persister."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from pathlib import Path

import pytest

from agent.event_bus import EventBus
from agent.parsers.base import NormalizedEvent, Severity
from api.models.database import DatabaseManager
from api.models.persistence import EventPersister


def _event(**overrides: object) -> NormalizedEvent:
    defaults: dict[str, object] = {
        "timestamp": datetime(2026, 4, 9, 12, 0, 0),
        "source": "dns",
        "event_type": "dns_query",
        "severity": Severity.INFO,
        "raw_message": "query[A] example.com from 10.0.0.2",
        "source_ip": "10.0.0.2",
        "dest_port": 53,
        "metadata": {"domain": "example.com", "query_type": "A"},
    }
    defaults.update(overrides)
    return NormalizedEvent(**defaults)  # type: ignore[arg-type]


async def _wait_for(predicate, timeout: float = 3.0) -> None:
    async def _poll() -> None:
        while not predicate():
            await asyncio.sleep(0.02)

    await asyncio.wait_for(_poll(), timeout=timeout)


@pytest.fixture
def db(tmp_path: Path) -> DatabaseManager:
    manager = DatabaseManager(tmp_path / "test.db")
    manager.initialize()
    return manager


@pytest.mark.asyncio
async def test_published_events_reach_database(db: DatabaseManager) -> None:
    """Events published to the bus land in the events table."""
    bus = EventBus()
    persister = EventPersister(bus, db)
    task = asyncio.create_task(persister.start())
    await asyncio.wait_for(persister.ready.wait(), timeout=3.0)

    await bus.publish(_event())
    await bus.publish(_event(
        source="auth",
        event_type="ssh_failed",
        severity=Severity.MEDIUM,
        raw_message="Failed password for admin from 10.0.0.9 port 4242 ssh2",
        source_ip="10.0.0.9",
        dest_port=22,
        metadata={"username": "admin"},
    ))

    await _wait_for(lambda: persister.events_persisted >= 2)

    with db.connect() as conn:
        rows = conn.execute("SELECT * FROM events ORDER BY id").fetchall()
    assert len(rows) == 2
    assert rows[0]["source"] == "dns"
    assert json.loads(rows[0]["metadata"])["domain"] == "example.com"
    assert rows[1]["event_type"] == "ssh_failed"
    assert rows[1]["severity"] == "medium"

    await persister.stop()
    task.cancel()


@pytest.mark.asyncio
async def test_persisted_events_are_full_text_searchable(db: DatabaseManager) -> None:
    """The fts triggers index persister writes like any other insert."""
    bus = EventBus()
    persister = EventPersister(bus, db)
    task = asyncio.create_task(persister.start())
    await asyncio.wait_for(persister.ready.wait(), timeout=3.0)

    await bus.publish(_event(
        raw_message="query[TXT] deadbeef.tunnel.evil.com from 10.0.0.7",
    ))
    await _wait_for(lambda: persister.events_persisted >= 1)

    with db.connect() as conn:
        n = conn.execute(
            "SELECT COUNT(*) FROM events_fts WHERE events_fts MATCH 'tunnel'"
        ).fetchone()[0]
    assert n == 1

    await persister.stop()
    task.cancel()


@pytest.mark.asyncio
async def test_bad_event_does_not_discard_batch(db: DatabaseManager) -> None:
    """A CHECK-violating event is dropped alone; neighbours still persist."""
    bus = EventBus()
    persister = EventPersister(bus, db)
    task = asyncio.create_task(persister.start())
    await asyncio.wait_for(persister.ready.wait(), timeout=3.0)

    # 'bogus' violates the events.source CHECK constraint.
    await bus.publish(_event(source="bogus"))
    await bus.publish(_event(raw_message="query[A] survivor.example.org from 10.0.0.2"))

    await _wait_for(lambda: persister.events_persisted >= 1)

    with db.connect() as conn:
        rows = conn.execute("SELECT raw_message FROM events").fetchall()
    messages = [row["raw_message"] for row in rows]
    assert any("survivor.example.org" in m for m in messages)
    assert not any("bogus" in m for m in messages)

    await persister.stop()
    task.cancel()
