"""Alert management endpoints."""

from __future__ import annotations

import re

from fastapi import APIRouter, HTTPException, Request

__all__ = ["router"]

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])

_ALERT_ID_RE = re.compile(r"^[0-9]{1,20}$")


def _validate_alert_id(alert_id: str) -> int:
    if not _ALERT_ID_RE.match(alert_id):
        raise HTTPException(status_code=400, detail="Invalid alert ID format")
    return int(alert_id)


@router.get("")
async def list_alerts(
    request: Request,
    acknowledged: bool | None = None,
    severity: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, object]:
    """List alerts with optional filtering."""
    db = request.app.state.db
    conditions: list[str] = []
    params: list[object] = []

    if acknowledged is not None:
        conditions.append("acknowledged = ?")
        params.append(1 if acknowledged else 0)
    if severity:
        conditions.append("severity = ?")
        params.append(severity)

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    with db.connect() as conn:
        count_row = conn.execute(
            f"SELECT COUNT(*) FROM alerts {where}", params  # noqa: S608
        ).fetchone()
        total = count_row[0] if count_row else 0

        rows = conn.execute(
            f"SELECT * FROM alerts {where} "  # noqa: S608
            f"ORDER BY created_at DESC LIMIT ? OFFSET ?",
            [*params, limit, offset],
        ).fetchall()

    return {"total": total, "alerts": [dict(r) for r in rows]}


@router.post("/{alert_id}/acknowledge")
async def acknowledge_alert(request: Request, alert_id: str) -> dict[str, str]:
    """Mark an alert as reviewed."""
    aid = _validate_alert_id(alert_id)
    db = request.app.state.db

    with db.connect() as conn:
        row = conn.execute("SELECT id FROM alerts WHERE id = ?", (aid,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Alert not found")
        conn.execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (aid,))

    return {"status": "acknowledged"}
