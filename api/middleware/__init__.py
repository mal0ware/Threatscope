"""API middleware: JWT authentication and per-IP rate limiting."""

from __future__ import annotations

from api.middleware.auth import (
    ADMIN_SCOPE,
    READ_SCOPE,
    VALID_SCOPES,
    AuthError,
    JWTAuthMiddleware,
    authenticate,
    authenticate_websocket,
    issue_token,
    verify_token,
)
from api.middleware.ratelimit import FixedWindowRateLimiter, RateLimitMiddleware

__all__ = [
    "ADMIN_SCOPE",
    "READ_SCOPE",
    "VALID_SCOPES",
    "AuthError",
    "FixedWindowRateLimiter",
    "JWTAuthMiddleware",
    "RateLimitMiddleware",
    "authenticate",
    "authenticate_websocket",
    "issue_token",
    "verify_token",
]
