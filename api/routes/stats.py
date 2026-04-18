"""Dashboard statistics endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Request

__all__ = ["router"]

router = APIRouter(prefix="/api/v1/stats", tags=["stats"])


@router.get("/overview")
async def overview(request: Request) -> dict[str, object]:
    """Dashboard summary: event counts, alert counts, top sources."""
    db = request.app.state.db

    with db.connect() as conn:
        total_events = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]

        events_1h = conn.execute(
            "SELECT COUNT(*) FROM events WHERE timestamp >= datetime('now', '-1 hour')"
        ).fetchone()[0]

        severity_counts = conn.execute(
            "SELECT severity, COUNT(*) as count FROM events "
            "GROUP BY severity ORDER BY count DESC"
        ).fetchall()

        open_alerts = conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE acknowledged = 0"
        ).fetchone()[0]

        top_source_ips = conn.execute(
            "SELECT source_ip, COUNT(*) as count FROM events "
            "WHERE source_ip IS NOT NULL "
            "GROUP BY source_ip ORDER BY count DESC LIMIT 10"
        ).fetchall()

        top_event_types = conn.execute(
            "SELECT event_type, COUNT(*) as count FROM events "
            "GROUP BY event_type ORDER BY count DESC LIMIT 10"
        ).fetchall()

    return {
        "total_events": total_events,
        "events_last_hour": events_1h,
        "severity_breakdown": {r["severity"]: r["count"] for r in severity_counts},
        "open_alerts": open_alerts,
        "top_source_ips": [
            {"ip": r["source_ip"], "count": r["count"]} for r in top_source_ips
        ],
        "top_event_types": [
            {"type": r["event_type"], "count": r["count"]} for r in top_event_types
        ],
    }


@router.get("/heatmap")
async def heatmap(request: Request) -> dict[str, object]:
    """Hourly event heatmap data (24h x 7d grid)."""
    db = request.app.state.db

    with db.connect() as conn:
        rows = conn.execute(
            "SELECT "
            "  CAST(strftime('%w', timestamp) AS INTEGER) AS day_of_week, "
            "  CAST(strftime('%H', timestamp) AS INTEGER) AS hour, "
            "  COUNT(*) AS count "
            "FROM events "
            "WHERE timestamp >= datetime('now', '-7 days') "
            "GROUP BY day_of_week, hour "
            "ORDER BY day_of_week, hour"
        ).fetchall()

    return {
        "period_days": 7,
        "buckets": [
            {"day": r["day_of_week"], "hour": r["hour"], "count": r["count"]}
            for r in rows
        ],
    }
