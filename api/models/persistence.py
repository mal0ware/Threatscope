"""Persist normalized events from the event bus into SQLite.

The persister is a bus subscriber that sits alongside the ML pipeline:
every event published by the collectors (file tailer, demo replay) is
written to the ``events`` table, which keeps it queryable through the
REST API, searchable via fts5 (the sync triggers index each insert), and
visible on the dashboard. Without it, tailed log events would flow to
detectors and WebSocket clients but never reach storage.
"""

from __future__ import annotations

import asyncio
import json
import logging
import sqlite3

from agent.event_bus import EventBus
from agent.parsers.base import NormalizedEvent
from api.models.database import DatabaseManager

__all__ = ["EventPersister"]

logger = logging.getLogger(__name__)

_SUBSCRIBER_ID = "event-persister"
_MAX_BATCH = 200

_INSERT_SQL = (
    "INSERT INTO events (timestamp, source, event_type, severity, "
    "source_ip, dest_ip, dest_port, raw_message, metadata) "
    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
)


def _to_row(event: NormalizedEvent) -> tuple[object, ...]:
    return (
        event.timestamp.isoformat(),
        event.source,
        event.event_type,
        event.severity.value,
        event.source_ip,
        event.dest_ip,
        event.dest_port,
        event.raw_message,
        json.dumps(event.metadata),
    )


class EventPersister:
    """Consumes events from the bus and writes them to the events table.

    Events are drained in batches (single connection/transaction per
    batch) to keep write amplification low under bursty log traffic.
    A batch that fails wholesale — e.g. one event violates a CHECK
    constraint — is retried row by row so a single bad event cannot
    discard its neighbours.
    """

    def __init__(self, event_bus: EventBus, db: DatabaseManager) -> None:
        self._event_bus = event_bus
        self._db = db
        self._running = False
        self._ready = asyncio.Event()
        self._events_persisted = 0

    @property
    def events_persisted(self) -> int:
        return self._events_persisted

    @property
    def ready(self) -> asyncio.Event:
        """Set once the persister has subscribed to the bus."""
        return self._ready

    async def start(self) -> None:
        """Subscribe to the event bus and persist events until stopped."""
        queue = await self._event_bus.subscribe(_SUBSCRIBER_ID)
        self._running = True
        self._ready.set()
        logger.info("Event persister started")

        try:
            while self._running:
                try:
                    first = await asyncio.wait_for(queue.get(), timeout=1.0)
                except TimeoutError:
                    continue
                batch = [first]
                while len(batch) < _MAX_BATCH:
                    try:
                        batch.append(queue.get_nowait())
                    except asyncio.QueueEmpty:
                        break
                self._write_batch(batch)
        except asyncio.CancelledError:
            pass
        finally:
            await self._event_bus.unsubscribe(_SUBSCRIBER_ID)
            logger.info(
                "Event persister stopped after writing %d events",
                self._events_persisted,
            )

    async def stop(self) -> None:
        self._running = False

    def _write_batch(self, batch: list[NormalizedEvent]) -> None:
        rows = [_to_row(event) for event in batch]
        try:
            with self._db.connect() as conn:
                conn.executemany(_INSERT_SQL, rows)
            self._events_persisted += len(rows)
        except sqlite3.Error:
            # One malformed event (e.g. a source outside the schema's CHECK
            # allowlist) must not take down the whole batch.
            self._write_rows_individually(rows)

    def _write_rows_individually(self, rows: list[tuple[object, ...]]) -> None:
        for row in rows:
            try:
                with self._db.connect() as conn:
                    conn.execute(_INSERT_SQL, row)
                self._events_persisted += 1
            except sqlite3.Error as exc:
                logger.warning(
                    "Dropping unpersistable event (%s): source=%r type=%r",
                    exc,
                    row[1],
                    row[2],
                )
