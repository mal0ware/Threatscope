"""Anomaly detection and narrative endpoints."""

from __future__ import annotations

import json
import re

from fastapi import APIRouter, HTTPException, Request

__all__ = ["router"]

router = APIRouter(prefix="/api/v1/anomalies", tags=["anomalies"])

_ID_RE = re.compile(r"^[0-9]{1,20}$")


@router.get("")
async def list_anomalies(
    request: Request,
    min_score: float = 0.5,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, object]:
    """List events with anomaly scores above the threshold."""
    db = request.app.state.db

    with db.connect() as conn:
        count_row = conn.execute(
            "SELECT COUNT(*) FROM events WHERE anomaly_score >= ?",
            (min_score,),
        ).fetchone()
        total = count_row[0] if count_row else 0

        rows = conn.execute(
            "SELECT * FROM events WHERE anomaly_score >= ? "
            "ORDER BY anomaly_score DESC LIMIT ? OFFSET ?",
            (min_score, limit, offset),
        ).fetchall()

    return {"total": total, "anomalies": [dict(r) for r in rows]}


@router.get("/{alert_id}/narrative")
async def get_narrative(request: Request, alert_id: str) -> dict[str, object]:
    """Get the threat narrative for an alert."""
    if not _ID_RE.match(alert_id):
        raise HTTPException(status_code=400, detail="Invalid alert ID format")

    db = request.app.state.db

    with db.connect() as conn:
        row = conn.execute(
            "SELECT * FROM alerts WHERE id = ?", (int(alert_id),)
        ).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")

    alert = dict(row)
    return {
        "alert_id": alert["id"],
        "severity": alert["severity"],
        "narrative": alert["narrative"] or "No narrative available.",
        "event_cluster": json.loads(alert["event_cluster"]),
    }
