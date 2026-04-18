"""Tests for the in-memory event bus."""

import pytest

from agent.event_bus import EventBus
from agent.parsers.base import NormalizedEvent, Severity

_SAMPLE_EVENT = NormalizedEvent(
    timestamp=__import__("datetime").datetime(2026, 4, 9, 12, 0, 0),
    source="auth",
    event_type="ssh_failed",
    severity=Severity.MEDIUM,
    raw_message="Failed password for admin from 10.0.0.1 port 22",
    source_ip="10.0.0.1",
    dest_port=22,
)


@pytest.mark.asyncio
async def test_publish_stores_in_buffer():
    bus = EventBus(buffer_size=100)
    await bus.publish(_SAMPLE_EVENT)
    assert bus.buffer_size == 1
    assert bus.get_recent(1) == [_SAMPLE_EVENT]


@pytest.mark.asyncio
async def test_subscribe_receives_events():
    bus = EventBus()
    queue = await bus.subscribe("test-sub")
    await bus.publish(_SAMPLE_EVENT)
    event = queue.get_nowait()
    assert event == _SAMPLE_EVENT


@pytest.mark.asyncio
async def test_unsubscribe_removes_subscriber():
    bus = EventBus()
    await bus.subscribe("test-sub")
    assert bus.subscriber_count == 1
    await bus.unsubscribe("test-sub")
    assert bus.subscriber_count == 0


@pytest.mark.asyncio
async def test_ring_buffer_evicts_oldest():
    bus = EventBus(buffer_size=5)
    for i in range(10):
        event = NormalizedEvent(
            timestamp=__import__("datetime").datetime(2026, 1, 1, 0, 0, i),
            source="auth",
            event_type=f"event_{i}",
            severity=Severity.INFO,
            raw_message=f"event {i}",
        )
        await bus.publish(event)
    assert bus.buffer_size == 5
    recent = bus.get_recent(5)
    assert recent[0].event_type == "event_5"
    assert recent[-1].event_type == "event_9"


@pytest.mark.asyncio
async def test_slow_consumer_does_not_block():
    bus = EventBus()
    queue = await bus.subscribe("slow", maxsize=2)

    for i in range(10):
        event = NormalizedEvent(
            timestamp=__import__("datetime").datetime(2026, 1, 1, 0, 0, i),
            source="auth",
            event_type=f"event_{i}",
            severity=Severity.INFO,
            raw_message=f"event {i}",
        )
        await bus.publish(event)

    # Queue should still be functional (not deadlocked)
    assert not queue.empty()


@pytest.mark.asyncio
async def test_get_recent_by_severity():
    bus = EventBus()
    await bus.publish(_SAMPLE_EVENT)
    await bus.publish(
        NormalizedEvent(
            timestamp=__import__("datetime").datetime(2026, 4, 9, 12, 1, 0),
            source="syslog",
            event_type="syslog_cron",
            severity=Severity.INFO,
            raw_message="CRON job",
        )
    )
    medium_events = bus.get_recent_by_severity("medium")
    assert len(medium_events) == 1
    assert medium_events[0].severity == Severity.MEDIUM
