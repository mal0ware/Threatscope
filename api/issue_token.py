"""CLI to mint a signed JWT for the ThreatScope API.

Usage::

    python -m api.issue_token --scope read
    python -m api.issue_token --scope admin --expiry-minutes 1440

The token is signed with the configured ``THREATSCOPE_JWT_SECRET``. If no
secret is set the command exits with an error, since an unsigned/empty-secret
token would be worthless. The minted token is printed to stdout so it can be
piped or copied directly into an ``Authorization: Bearer <token>`` header.
"""

from __future__ import annotations

import argparse
import sys

from agent.config import get_settings
from api.middleware.auth import VALID_SCOPES, issue_token


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m api.issue_token",
        description="Issue a signed JWT bearer token for the ThreatScope API.",
    )
    parser.add_argument(
        "--scope",
        required=True,
        choices=sorted(VALID_SCOPES),
        help="Token scope: 'read' for read-only routes, 'admin' for everything.",
    )
    parser.add_argument(
        "--expiry-minutes",
        type=int,
        default=None,
        help="Token lifetime in minutes (default: jwt_expiry_minutes from config).",
    )
    args = parser.parse_args(argv)

    settings = get_settings()
    if not settings.jwt_secret:
        print(
            "error: THREATSCOPE_JWT_SECRET is not set. Authentication is disabled "
            "and there is nothing to sign a token with.",
            file=sys.stderr,
        )
        return 1

    expiry = args.expiry_minutes if args.expiry_minutes is not None else settings.jwt_expiry_minutes
    token = issue_token(
        settings.jwt_secret,
        args.scope,
        algorithm=settings.jwt_algorithm,
        expiry_minutes=expiry,
    )
    print(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
