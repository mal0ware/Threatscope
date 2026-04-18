"""In-memory event bus backed by asyncio.Queue and a fixed-size ring buffer.

The event bus decouples log ingestion from downstream consumers (API, ML
pipeline, WebSocket clients). New events are broadcast to all registered
subscriber queues and retained in a ring buffer for recent-history queries.
"""

from __future__ import annotations

import asyncio
import logging
from collections import deque

from agent.parsers.base import NormalizedEvent

__all__ = ["EventBus"]

logger = logging.getLogger(__name__)

_DEFAULT_BUFFER_SIZE = 10_000
_DEFAULT_SUBSCRIBER_MAXSIZE = 1_000


class EventBus:
    """Publish-subscribe event bus with bounded ring buffer.

    Thread-safe for single-threaded asyncio usage. Each subscriber gets
    its own bounded queue — slow consumers drop oldest events rather than
    blocking producers.
    """

    def __init__(self, buffer_size: int = _DEFAULT_BUFFER_SIZE) -> None:
        self._buffer: deque[NormalizedEvent] = deque(maxlen=buffer_size)
        self._subscribers: dict[str, asyncio.Queue[NormalizedEvent]] = {}
        self._lock = asyncio.Lock()

    @property
    def buffer_size(self) -> int:
        return len(self._buffer)

    @property
    def subscriber_count(self) -> int:
        return len(self._subscribers)

    async def publish(self, event: NormalizedEvent) -> None:
        """Publish an event to all subscribers and the ring buffer."""
        self._buffer.append(event)

        for _sub_id, queue in self._subscribers.items():
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                # Drop oldest event from slow consumer to prevent backpressure
                try:
                    queue.get_nowait()
                    queue.put_nowait(event)
                except asyncio.QueueEmpty:
                    pass

    async def subscribe(
        self, subscriber_id: str, maxsize: int = _DEFAULT_SUBSCRIBER_MAXSIZE
    ) -> asyncio.Queue[NormalizedEvent]:
        """Register a subscriber and return its dedicated event queue."""
        async with self._lock:
            if subscriber_id in self._subscribers:
                logger.warning("Subscriber %s already registered, replacing", subscriber_id)
            queue: asyncio.Queue[NormalizedEvent] = asyncio.Queue(maxsize=maxsize)
            self._subscribers[subscriber_id] = queue
            logger.info("Subscriber %s registered", subscriber_id)
            return queue

    async def unsubscribe(self, subscriber_id: str) -> None:
        """Remove a subscriber."""
        async with self._lock:
            self._subscribers.pop(subscriber_id, None)
            logger.info("Subscriber %s unregistered", subscriber_id)

    def get_recent(self, count: int = 100) -> list[NormalizedEvent]:
        """Return the most recent events from the ring buffer."""
        if count >= len(self._buffer):
            return list(self._buffer)
        return list(self._buffer)[-count:]

    def get_recent_by_severity(
        self, severity: str, count: int = 100
    ) -> list[NormalizedEvent]:
        """Return recent events filtered by severity level."""
        matching = [e for e in self._buffer if e.severity.value == severity]
        return matching[-count:]
