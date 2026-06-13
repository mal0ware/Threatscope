"""Per-IP request rate limiting.

A fixed-window counter keyed on the client IP, honoring the configured
``rate_limit_per_minute``. When a client exceeds its budget within the current
60-second window the request is rejected with ``429 Too Many Requests`` and a
``Retry-After`` header indicating how many seconds remain in the window.

The limiter is active whenever ``rate_limit_per_minute`` is greater than zero
(the default is 60). Setting it to ``0`` disables limiting — useful for tests
and trusted internal deployments. Counters live in process memory; this is a
single-node limiter, not a distributed one.
"""

from __future__ import annotations

import threading
import time
from typing import TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from starlette.types import ASGIApp

    from agent.config import Settings

__all__ = ["RateLimitMiddleware", "FixedWindowRateLimiter"]

_WINDOW_SECONDS = 60.0

# Paths exempt from rate limiting (cheap liveness probe).
_EXEMPT_PATHS = frozenset({"/health"})


class FixedWindowRateLimiter:
    """Thread-safe fixed-window per-key request counter.

    Each key (client IP) accumulates a count within a rolling 60-second window.
    When the window elapses the count resets. ``check`` atomically records a hit
    and reports whether the caller is now over budget.
    """

    def __init__(self, limit_per_minute: int, *, window_seconds: float = _WINDOW_SECONDS) -> None:
        self._limit = limit_per_minute
        self._window = window_seconds
        # key -> (window_start_monotonic, count)
        self._hits: dict[str, tuple[float, int]] = {}
        self._lock = threading.Lock()

    @property
    def limit(self) -> int:
        return self._limit

    def check(self, key: str, *, now: float | None = None) -> tuple[bool, int]:
        """Record a hit for ``key``.

        Returns ``(allowed, retry_after_seconds)``. When allowed,
        ``retry_after_seconds`` is ``0``.
        """
        current = time.monotonic() if now is None else now
        with self._lock:
            window_start, count = self._hits.get(key, (current, 0))

            # Reset the window if it has fully elapsed.
            if current - window_start >= self._window:
                window_start, count = current, 0

            if count >= self._limit:
                remaining = self._window - (current - window_start)
                retry_after = max(1, int(remaining) + (1 if remaining % 1 else 0))
                # Do not advance the counter on a rejected request.
                self._hits[key] = (window_start, count)
                return False, retry_after

            self._hits[key] = (window_start, count + 1)
            return True, 0


def _client_ip(request: Request) -> str:
    """Best-effort client IP for keying the limiter."""
    client = request.client
    if client is not None and client.host:
        return client.host
    return "unknown"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Reject requests from an IP that exceeds the configured per-minute budget."""

    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        super().__init__(app)
        self._enabled = settings.rate_limit_per_minute > 0
        self._limiter = FixedWindowRateLimiter(settings.rate_limit_per_minute)

    async def dispatch(
        self,
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        if not self._enabled or request.url.path in _EXEMPT_PATHS:
            return await call_next(request)

        allowed, retry_after = self._limiter.check(_client_ip(request))
        if not allowed:
            return JSONResponse(
                {"detail": "Rate limit exceeded"},
                status_code=429,
                headers={
                    "Retry-After": str(retry_after),
                    "X-RateLimit-Limit": str(self._limiter.limit),
                },
            )

        return await call_next(request)
