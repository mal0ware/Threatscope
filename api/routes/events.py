"""Event search, retrieval, and SSE streaming endpoints."""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator
from datetime import datetime

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

__all__ = ["router"]

router = APIRouter(prefix="/api/v1/events", tags=["events"])

_EVENT_ID_RE = re.compile(r"^[0-9]{1,20}$")
_SEVERITY_ALLOWED = frozenset({"info", "low", "medium", "high", "critical"})
_SOURCE_ALLOWED = frozenset({"auth", "syslog", "network", "dns"})
_SORT_ALLOWED = frozenset({"timestamp", "severity", "source"})
_MAX_LIMIT = 500


def _validate_event_id(event_id: str) -> int:
    if not _EVENT_ID_RE.match(event_id):
        raise HTTPException(status_code=400, detail="Invalid event ID format")
    return int(event_id)


@router.get("/search")
async def search_events(
    request: Request,
    q: str | None = Query(None, max_length=200, description="Full-text search query"),
    severity: str | None = Query(None, description="Filter by severity level"),
    source: str | None = Query(None, description="Filter by log source"),
    event_type: str | None = Query(None, max_length=100, description="Filter by event type"),
    source_ip: str | None = Query(None, max_length=45, description="Filter by source IP"),
    start: str | None = Query(None, description="Start timestamp (ISO 8601)"),
    end: str | None = Query(None, description="End timestamp (ISO 8601)"),
    sort: str = Query("timestamp", description="Sort field"),
    order: str = Query("desc", description="Sort order (asc/desc)"),
    limit: int = Query(50, ge=1, le=_MAX_LIMIT, description="Results per page"),
    offset: int = Query(0, ge=0, description="Pagination offset"),
) -> dict[str, object]:
    """Search events with filtering, full-text search, and pagination."""
    if severity and severity not in _SEVERITY_ALLOWED:
        raise HTTPException(status_code=400, detail=f"Invalid severity: {severity}")
    if source and source not in _SOURCE_ALLOWED:
        raise HTTPException(status_code=400, detail=f"Invalid source: {source}")
    if sort not in _SORT_ALLOWED:
        raise HTTPException(status_code=400, detail=f"Invalid sort field: {sort}")
    if order not in ("asc", "desc"):
        raise HTTPException(status_code=400, detail="Order must be 'asc' or 'desc'")

    # Validate timestamps
    for ts_name, ts_val in [("start", start), ("end", end)]:
        if ts_val:
            try:
                datetime.fromisoformat(ts_val)
            except ValueError:
                raise HTTPException(  # noqa: B904
                    status_code=400, detail=f"Invalid {ts_name} timestamp"
                )

    db = request.app.state.db

    # Build parameterized query
    conditions: list[str] = []
    params: list[object] = []

    if q:
        conditions.append("e.id IN (SELECT rowid FROM events_fts WHERE events_fts MATCH ?)")
        params.append(q)
    if severity:
        conditions.append("e.severity = ?")
        params.append(severity)
    if source:
        conditions.append("e.source = ?")
        params.append(source)
    if event_type:
        conditions.append("e.event_type = ?")
        params.append(event_type)
    if source_ip:
        conditions.append("e.source_ip = ?")
        params.append(source_ip)
    if start:
        conditions.append("e.timestamp >= ?")
        params.append(start)
    if end:
        conditions.append("e.timestamp <= ?")
        params.append(end)

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    sort_col = {"timestamp": "e.timestamp", "severity": "e.severity", "source": "e.source"}[sort]
    direction = "DESC" if order == "desc" else "ASC"

    with db.connect() as conn:
        count_row = conn.execute(
            f"SELECT COUNT(*) FROM events e {where}", params  # noqa: S608
        ).fetchone()
        total = count_row[0] if count_row else 0

        rows = conn.execute(
            f"SELECT e.* FROM events e {where} "  # noqa: S608
            f"ORDER BY {sort_col} {direction} LIMIT ? OFFSET ?",
            [*params, limit, offset],
        ).fetchall()

    events = [dict(row) for row in rows]

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "events": events,
    }


@router.get("/stream")
async def stream_events(request: Request) -> StreamingResponse:
    """Server-Sent Events stream of real-time normalized events."""
    event_bus = request.app.state.event_bus
    queue = await event_bus.subscribe(f"sse-{id(request)}")

    async def event_generator() -> AsyncIterator[str]:
        try:
            while True:
                event = await queue.get()
                data = json.dumps(event.to_dict())
                yield f"data: {data}\n\n"
        except Exception:
            await event_bus.unsubscribe(f"sse-{id(request)}")

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/{event_id}")
async def get_event(request: Request, event_id: str) -> dict[str, object]:
    """Retrieve a single event by ID."""
    eid = _validate_event_id(event_id)
    db = request.app.state.db

    with db.connect() as conn:
        row = conn.execute("SELECT * FROM events WHERE id = ?", (eid,)).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Event not found")

    return {"event": dict(row)}
