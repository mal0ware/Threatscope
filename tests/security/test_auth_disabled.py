"""Tests that the demo path (no jwt_secret) bypasses auth entirely."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.asyncio


async def test_read_route_open_without_token(open_client) -> None:  # type: ignore[no-untyped-def]
    resp = await open_client.get("/api/v1/stats/overview")
    assert resp.status_code == 200


async def test_mutating_route_reaches_handler_without_token(open_client) -> None:  # type: ignore[no-untyped-def]
    # No auth gate: request reaches the handler, which 404s on a missing alert
    # (proving it was NOT blocked by a 401/403 first).
    resp = await open_client.post("/api/v1/alerts/99999/acknowledge")
    assert resp.status_code == 404


async def test_health_open(open_client) -> None:  # type: ignore[no-untyped-def]
    resp = await open_client.get("/health")
    assert resp.status_code == 200


async def test_garbage_token_ignored_when_auth_disabled(open_client) -> None:  # type: ignore[no-untyped-def]
    # A bogus token must not cause a 401 when auth is off — it's simply ignored.
    resp = await open_client.get(
        "/api/v1/stats/overview", headers={"Authorization": "Bearer not.a.jwt"}
    )
    assert resp.status_code == 200
