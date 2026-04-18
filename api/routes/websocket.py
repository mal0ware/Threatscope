"""WebSocket endpoint for real-time event push to dashboard clients."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

__all__ = ["router"]

logger = logging.getLogger(__name__)

router = APIRouter(tags=["websocket"])

_MAX_WS_CONNECTIONS = 50
_active_connections: set[str] = set()


@router.websocket("/ws/events")
async def websocket_events(websocket: WebSocket) -> None:
    """Push real-time events to connected dashboard clients."""
    if len(_active_connections) >= _MAX_WS_CONNECTIONS:
        await websocket.close(code=1013, reason="Too many connections")
        return

    await websocket.accept()
    conn_id = f"ws-{id(websocket)}"
    _active_connections.add(conn_id)

    event_bus = websocket.app.state.event_bus
    queue = await event_bus.subscribe(conn_id)

    logger.info("WebSocket client connected: %s", conn_id)

    try:
        # Run consumer and keepalive in parallel
        consumer_task = asyncio.create_task(_push_events(websocket, queue))
        ping_task = asyncio.create_task(_keepalive(websocket))

        done, pending = await asyncio.wait(
            {consumer_task, ping_task},
            return_when=asyncio.FIRST_COMPLETED,
        )

        for task in pending:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError, WebSocketDisconnect):
                await task

    except WebSocketDisconnect:
        pass
    finally:
        await event_bus.unsubscribe(conn_id)
        _active_connections.discard(conn_id)
        logger.info("WebSocket client disconnected: %s", conn_id)


async def _push_events(
    websocket: WebSocket, queue: asyncio.Queue[object]
) -> None:
    """Forward events from the subscriber queue to the WebSocket client."""
    while True:
        event = await queue.get()
        data = json.dumps(event.to_dict())  # type: ignore[attr-defined]
        await websocket.send_text(data)


async def _keepalive(websocket: WebSocket, interval: float = 30.0) -> None:
    """Send periodic pings to detect stale connections."""
    while True:
        await asyncio.sleep(interval)
        await websocket.send_json({"type": "ping"})
