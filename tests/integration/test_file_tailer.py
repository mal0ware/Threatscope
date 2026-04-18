"""Integration tests for the file tailer → parser → event bus pipeline."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from agent.collectors.file_tailer import FileTailer
from agent.event_bus import EventBus
from agent.parsers.auth import AuthLogParser
from agent.parsers.base import NormalizedEvent

_AUTH_LINE = (
    "Apr  9 12:34:56 server sshd[12345]: "
    "Failed password for admin from 192.168.1.100 port 22 ssh2"
)


@pytest.mark.asyncio
async def test_tailer_publishes_events(tmp_path: Path) -> None:
    """New lines appended to a tailed file are parsed and published."""
    log_file = tmp_path / "auth.log"
    log_file.write_text("")

    bus = EventBus()
    tailer = FileTailer(bus, poll_interval=0.1)
    tailer.add_source(log_file, AuthLogParser())

    queue = await bus.subscribe("test")
    task = asyncio.create_task(tailer.start())

    # Append a parsable auth log line
    with open(log_file, "a") as f:
        f.write(_AUTH_LINE + "\n")

    # Wait for the event to propagate
    event: NormalizedEvent = await asyncio.wait_for(queue.get(), timeout=3.0)

    assert event.source == "auth"
    assert event.event_type == "ssh_failed"
    assert event.source_ip == "192.168.1.100"

    await tailer.stop()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_tailer_skips_existing_content(tmp_path: Path) -> None:
    """Tailer starts from end of file, ignoring pre-existing lines."""
    log_file = tmp_path / "auth.log"
    log_file.write_text(_AUTH_LINE + "\n")

    bus = EventBus()
    tailer = FileTailer(bus, poll_interval=0.1)
    tailer.add_source(log_file, AuthLogParser())

    queue = await bus.subscribe("test")
    task = asyncio.create_task(tailer.start())

    # Give tailer time to start and read (should find nothing new)
    await asyncio.sleep(0.5)
    assert queue.empty()

    await tailer.stop()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_tailer_handles_missing_source(tmp_path: Path) -> None:
    """Tailer gracefully skips a source that doesn't exist."""
    bus = EventBus()
    tailer = FileTailer(bus)
    tailer.add_source(tmp_path / "nonexistent.log", AuthLogParser())

    # No sources registered (skipped missing), so start returns immediately
    await tailer.start()
