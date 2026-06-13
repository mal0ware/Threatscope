"""Tests for WebSocket handshake authentication.

WebSocket upgrades skip the HTTP middleware stack, so auth is enforced inside
the handler. These use Starlette's synchronous WS TestClient (httpx's
ASGITransport does not speak the WebSocket protocol). The TestClient runs the
app lifespan, which wires up the DB, event bus, and detection pipeline.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from agent.config import Settings
from api.main import create_app
from tests.security.conftest import TEST_SECRET, admin_token, read_token


def _make_client(jwt_secret: str) -> Iterator[TestClient]:
    with TemporaryDirectory() as tmpdir:
        settings = Settings(
            db_path=Path(tmpdir) / "test.db",
            debug=True,
            jwt_secret=jwt_secret,
            rate_limit_per_minute=0,
        )
        app = create_app(settings)
        with TestClient(app) as client:
            yield client


@pytest.fixture
def auth_ws_client() -> Iterator[TestClient]:
    yield from _make_client(TEST_SECRET)


@pytest.fixture
def open_ws_client() -> Iterator[TestClient]:
    yield from _make_client("")


def test_ws_rejects_connection_without_token(auth_ws_client: TestClient) -> None:
    with pytest.raises(WebSocketDisconnect):  # noqa: SIM117
        with auth_ws_client.websocket_connect("/ws/events"):
            pass


def test_ws_rejects_bad_token(auth_ws_client: TestClient) -> None:
    with pytest.raises(WebSocketDisconnect):  # noqa: SIM117
        with auth_ws_client.websocket_connect("/ws/events?token=garbage"):
            pass


def test_ws_accepts_valid_read_token_via_query(auth_ws_client: TestClient) -> None:
    # A successful handshake means the keepalive ping loop is active; we just
    # confirm the connection opens without being closed during the handshake.
    with auth_ws_client.websocket_connect(f"/ws/events?token={read_token()}") as ws:
        ws.close()


def test_ws_accepts_valid_token_via_header(auth_ws_client: TestClient) -> None:
    with auth_ws_client.websocket_connect(
        "/ws/events", headers={"Authorization": f"Bearer {admin_token()}"}
    ) as ws:
        ws.close()


def test_ws_open_when_auth_disabled(open_ws_client: TestClient) -> None:
    # Demo path: no secret -> WS connects with no token.
    with open_ws_client.websocket_connect("/ws/events") as ws:
        ws.close()
