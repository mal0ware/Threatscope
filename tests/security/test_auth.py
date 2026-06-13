"""Tests for JWT bearer-token authentication and scope enforcement."""

from __future__ import annotations

import pytest

from api.middleware.auth import AuthError, issue_token, verify_token
from tests.security.conftest import (
    TEST_SECRET,
    admin_token,
    bearer,
    expired_token,
    no_scope_token,
    read_token,
    wrong_signature_token,
)

# --- Unit-level token verification ---------------------------------------


def test_verify_valid_token_returns_claims() -> None:
    claims = verify_token(read_token(), TEST_SECRET)
    assert claims.scope == "read"
    assert claims.expires_at > 0


def test_verify_expired_token_raises_401() -> None:
    with pytest.raises(AuthError) as exc:
        verify_token(expired_token(), TEST_SECRET)
    assert exc.value.status_code == 401


def test_verify_wrong_signature_raises_401() -> None:
    with pytest.raises(AuthError) as exc:
        verify_token(wrong_signature_token(), TEST_SECRET)
    assert exc.value.status_code == 401


def test_verify_garbage_token_raises_401() -> None:
    with pytest.raises(AuthError) as exc:
        verify_token("not.a.jwt", TEST_SECRET)
    assert exc.value.status_code == 401


def test_verify_token_without_scope_raises_401() -> None:
    with pytest.raises(AuthError) as exc:
        verify_token(no_scope_token(), TEST_SECRET)
    assert exc.value.status_code == 401


def test_issue_token_rejects_unknown_scope() -> None:
    with pytest.raises(ValueError):
        issue_token(TEST_SECRET, "superuser")


def test_issue_token_rejects_empty_secret() -> None:
    with pytest.raises(ValueError):
        issue_token("", "read")


# --- HTTP middleware: missing / bad tokens rejected -----------------------


@pytest.mark.asyncio
async def test_missing_token_rejected(auth_client) -> None:  # type: ignore[no-untyped-def]
    resp = await auth_client.get("/api/v1/stats/overview")
    assert resp.status_code == 401
    assert resp.headers.get("WWW-Authenticate") == "Bearer"


@pytest.mark.asyncio
async def test_expired_token_rejected(auth_client) -> None:  # type: ignore[no-untyped-def]
    resp = await auth_client.get(
        "/api/v1/stats/overview", headers=bearer(expired_token())
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_wrong_signature_rejected(auth_client) -> None:  # type: ignore[no-untyped-def]
    resp = await auth_client.get(
        "/api/v1/stats/overview", headers=bearer(wrong_signature_token())
    )
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_malformed_authorization_header_rejected(auth_client) -> None:  # type: ignore[no-untyped-def]
    resp = await auth_client.get(
        "/api/v1/stats/overview", headers={"Authorization": "Token abc123"}
    )
    assert resp.status_code == 401


# --- HTTP middleware: valid tokens accepted -------------------------------


@pytest.mark.asyncio
async def test_valid_read_token_accepted_on_read_route(auth_client) -> None:  # type: ignore[no-untyped-def]
    resp = await auth_client.get(
        "/api/v1/stats/overview", headers=bearer(read_token())
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_valid_admin_token_accepted_on_read_route(auth_client) -> None:  # type: ignore[no-untyped-def]
    resp = await auth_client.get(
        "/api/v1/stats/overview", headers=bearer(admin_token())
    )
    assert resp.status_code == 200


# --- Scope enforcement on mutating routes ---------------------------------


@pytest.mark.asyncio
async def test_read_scope_forbidden_on_mutating_route(auth_client) -> None:  # type: ignore[no-untyped-def]
    # Acknowledge is a POST -> requires admin. A read token must be 403, not 404.
    resp = await auth_client.post(
        "/api/v1/alerts/99999/acknowledge", headers=bearer(read_token())
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_admin_scope_allowed_on_mutating_route(auth_client) -> None:  # type: ignore[no-untyped-def]
    # Admin passes auth; the alert doesn't exist so the route itself 404s.
    resp = await auth_client.post(
        "/api/v1/alerts/99999/acknowledge", headers=bearer(admin_token())
    )
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_mutating_route_without_token_is_401_not_403(auth_client) -> None:  # type: ignore[no-untyped-def]
    resp = await auth_client.post("/api/v1/alerts/99999/acknowledge")
    assert resp.status_code == 401


# --- Public routes & token-in-query (SSE/WS transport) --------------------


@pytest.mark.asyncio
async def test_health_is_public_even_with_auth_enabled(auth_client) -> None:  # type: ignore[no-untyped-def]
    resp = await auth_client.get("/health")
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_token_accepted_via_query_param(auth_client) -> None:  # type: ignore[no-untyped-def]
    # SSE/WS clients pass the token as ?token= since they cannot set headers.
    resp = await auth_client.get(
        "/api/v1/stats/overview", params={"token": read_token()}
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_bad_query_token_rejected(auth_client) -> None:  # type: ignore[no-untyped-def]
    resp = await auth_client.get(
        "/api/v1/stats/overview", params={"token": "garbage"}
    )
    assert resp.status_code == 401
