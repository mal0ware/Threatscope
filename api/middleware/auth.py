"""JWT bearer-token authentication.

Authentication is *config-gated*: it activates only when a non-empty
``jwt_secret`` is configured. When the secret is empty (the default for the
local demo path) every request passes through untouched, so ``--demo`` and the
existing test suite keep working without tokens.

When a secret *is* set, every request to a protected route must carry a valid
HS256-signed bearer token. Tokens encode a ``scope`` claim:

* ``read``  — may call safe (read-only) routes.
* ``admin`` — may call everything, including mutating/config routes.

Scope is enforced by HTTP method: ``GET``/``HEAD``/``OPTIONS`` require ``read``;
any mutating method (``POST``/``PUT``/``PATCH``/``DELETE``) requires ``admin``.

WebSocket and SSE clients cannot always set an ``Authorization`` header, so the
token may also be supplied as a ``?token=`` query parameter. Both transports are
covered by the same verification logic (:func:`verify_token`).
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

import jwt
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Mapping

    from starlette.types import ASGIApp
    from starlette.websockets import WebSocket

    from agent.config import Settings

__all__ = [
    "READ_SCOPE",
    "ADMIN_SCOPE",
    "VALID_SCOPES",
    "AuthError",
    "JWTAuthMiddleware",
    "authenticate",
    "authenticate_websocket",
    "issue_token",
    "verify_token",
]

READ_SCOPE = "read"
ADMIN_SCOPE = "admin"
VALID_SCOPES = frozenset({READ_SCOPE, ADMIN_SCOPE})

# Methods that only read state. Everything else mutates and needs admin scope.
_READ_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

# Routes that must stay reachable without a token even when auth is enabled.
_PUBLIC_PATHS = frozenset({"/health"})


class AuthError(Exception):
    """Raised when a token is missing, malformed, expired, or under-scoped."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


@dataclass(frozen=True, slots=True)
class TokenClaims:
    """Decoded, validated claims from a bearer token."""

    scope: str
    expires_at: int


def issue_token(
    secret: str,
    scope: str,
    *,
    algorithm: str = "HS256",
    expiry_minutes: int = 60,
    issued_at: int | None = None,
) -> str:
    """Sign and return a JWT carrying the given scope.

    Raises ``ValueError`` for an empty secret or an unknown scope so the CLI
    fails loudly rather than minting a useless token.
    """
    if not secret:
        raise ValueError("Cannot issue a token without a jwt_secret")
    if scope not in VALID_SCOPES:
        raise ValueError(f"Unknown scope {scope!r}; expected one of {sorted(VALID_SCOPES)}")

    now = int(time.time()) if issued_at is None else issued_at
    payload = {
        "scope": scope,
        "iat": now,
        "exp": now + expiry_minutes * 60,
    }
    return jwt.encode(payload, secret, algorithm=algorithm)


def verify_token(token: str, secret: str, *, algorithm: str = "HS256") -> TokenClaims:
    """Decode and validate a token, returning its claims.

    Raises :class:`AuthError` (401) on any signature/expiry/format failure.
    """
    try:
        payload = jwt.decode(token, secret, algorithms=[algorithm])
    except jwt.ExpiredSignatureError as exc:
        raise AuthError(401, "Token has expired") from exc
    except jwt.InvalidTokenError as exc:
        # Covers bad signature, malformed token, wrong algorithm, etc.
        raise AuthError(401, "Invalid authentication token") from exc

    scope = payload.get("scope")
    if scope not in VALID_SCOPES:
        raise AuthError(401, "Token is missing a valid scope claim")

    return TokenClaims(scope=scope, expires_at=int(payload.get("exp", 0)))


def _token_from(
    headers: Mapping[str, str], query_params: Mapping[str, str]
) -> str | None:
    """Pull a bearer token from the Authorization header or ``?token=`` query."""
    header = headers.get("authorization")
    if header:
        parts = header.split(" ", 1)
        if len(parts) == 2 and parts[0].lower() == "bearer":
            return parts[1].strip()
        # Header present but not a well-formed bearer token.
        return None
    return query_params.get("token")


def _required_scope(method: str) -> str:
    return READ_SCOPE if method.upper() in _READ_METHODS else ADMIN_SCOPE


def authenticate(request: Request, settings: Settings) -> TokenClaims:
    """Authenticate and authorize an HTTP request against the route's scope.

    Caller is responsible for skipping this when auth is disabled. Raises
    :class:`AuthError` with the appropriate status code on failure.
    """
    token = _token_from(request.headers, request.query_params)
    if not token:
        raise AuthError(401, "Missing bearer token")

    claims = verify_token(
        token,
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )

    required = _required_scope(request.method)
    if required == ADMIN_SCOPE and claims.scope != ADMIN_SCOPE:
        raise AuthError(403, "Admin scope required for this operation")

    return claims


def authenticate_websocket(websocket: WebSocket, settings: Settings) -> TokenClaims:
    """Authenticate a WebSocket handshake.

    WebSocket upgrades skip the HTTP middleware stack, so the handler calls this
    directly before accepting the connection. A WS subscription is read-only, so
    a ``read`` scope token suffices. Token may be supplied via the
    ``Authorization`` header or a ``?token=`` query parameter. Raises
    :class:`AuthError` on failure; caller closes the socket.
    """
    token = _token_from(websocket.headers, websocket.query_params)
    if not token:
        raise AuthError(401, "Missing bearer token")

    return verify_token(
        token,
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )


class JWTAuthMiddleware(BaseHTTPMiddleware):
    """Enforce bearer-token auth on HTTP routes when a secret is configured.

    WebSocket connections bypass this middleware (Starlette routes them around
    the HTTP middleware stack) and are guarded explicitly in the WebSocket
    handler via :func:`authenticate`.
    """

    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        super().__init__(app)
        self._settings = settings

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        # Config gate: no secret means auth is disabled entirely.
        if not self._settings.jwt_secret:
            return await call_next(request)

        if request.url.path in _PUBLIC_PATHS:
            return await call_next(request)

        # Always allow CORS preflight through; it carries no credentials.
        if request.method == "OPTIONS":
            return await call_next(request)

        try:
            claims = authenticate(request, self._settings)
        except AuthError as exc:
            headers = {"WWW-Authenticate": "Bearer"} if exc.status_code == 401 else {}
            return JSONResponse(
                {"detail": exc.detail},
                status_code=exc.status_code,
                headers=headers,
            )

        request.state.auth = claims
        return await call_next(request)
