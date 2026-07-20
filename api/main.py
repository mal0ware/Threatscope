"""ThreatScope API server entrypoint."""

from __future__ import annotations

import argparse
import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from agent.collectors.file_tailer import FileTailer
from agent.config import Settings, get_settings
from agent.event_bus import EventBus
from agent.parsers import parser_for_path
from api.middleware.auth import JWTAuthMiddleware
from api.middleware.ratelimit import RateLimitMiddleware
from api.models.database import DatabaseManager
from api.models.persistence import EventPersister
from api.routes import alerts, anomalies, events, stats, websocket
from ml.pipeline import DetectionPipeline

logger = logging.getLogger("threatscope")


def _configure_logging(debug: bool = False) -> None:
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-8s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Startup/shutdown lifecycle handler."""
    settings: Settings = app.state.settings
    db = DatabaseManager(settings.db_path)
    db.initialize()
    app.state.db = db
    app.state.event_bus = EventBus()

    # Start ML detection pipeline as background task
    pipeline = DetectionPipeline(app.state.event_bus, db)
    pipeline_task = asyncio.create_task(pipeline.start())
    app.state.pipeline = pipeline

    # Persist every bus event to SQLite so tailed logs reach the API/dashboard
    persister = EventPersister(app.state.event_bus, db)
    persister_task = asyncio.create_task(persister.start())
    app.state.persister = persister

    # Tail configured log files, routing each to its parser by filename.
    # Missing files are skipped, so the default source list is safe anywhere.
    tailer = FileTailer(app.state.event_bus)
    for source in settings.log_sources:
        tailer.add_source(source, parser_for_path(source))
    tailer_task = asyncio.create_task(tailer.start())
    app.state.tailer = tailer

    if settings.demo_mode:
        from scripts.generate_demo_data import generate_live_events, seed_database

        seed_database(db)
        # Replay a live attack burst through the bus so the detectors fire
        # real alerts. Wait for the consumers to subscribe first — events
        # published before subscription would vanish.
        await asyncio.wait_for(pipeline.ready.wait(), timeout=5.0)
        await asyncio.wait_for(persister.ready.wait(), timeout=5.0)
        for event in generate_live_events():
            await app.state.event_bus.publish(event)
        logger.info("Demo data seeded and live events replayed through the bus")

    logger.info(
        "ThreatScope started on %s:%d (demo=%s)",
        settings.host,
        settings.port,
        settings.demo_mode,
    )
    yield
    await tailer.stop()
    await pipeline.stop()
    await persister.stop()
    for task in (tailer_task, pipeline_task, persister_task):
        task.cancel()
    logger.info("ThreatScope shutting down")


def create_app(settings: Settings | None = None) -> FastAPI:
    """Application factory."""
    if settings is None:
        settings = get_settings()

    app = FastAPI(
        title="ThreatScope",
        description="Real-Time Network Threat Intelligence API",
        version="0.1.0",
        docs_url="/docs" if settings.debug else None,
        redoc_url=None,
        lifespan=lifespan,
    )
    app.state.settings = settings

    # Middleware runs in reverse order of registration (last added is
    # outermost). We want: rate limit -> auth -> CORS -> routes, so that
    # abusive traffic is shed before signature verification, and CORS headers
    # are applied to auth/rate-limit responses too.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )
    # Auth is config-gated inside the middleware: a no-op unless jwt_secret set.
    app.add_middleware(JWTAuthMiddleware, settings=settings)
    # Rate limiting is active whenever rate_limit_per_minute > 0.
    app.add_middleware(RateLimitMiddleware, settings=settings)

    # Register route modules
    app.include_router(events.router)
    app.include_router(alerts.router)
    app.include_router(anomalies.router)
    app.include_router(stats.router)
    app.include_router(websocket.router)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": "0.1.0"}

    return app


def main() -> None:
    parser = argparse.ArgumentParser(description="ThreatScope API Server")
    parser.add_argument("--demo", action="store_true", help="Run with synthetic event generation")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging and docs")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    _configure_logging(debug=args.debug)

    settings = get_settings()
    settings = Settings(
        host=args.host,
        port=args.port,
        debug=args.debug,
        demo_mode=args.demo,
        db_path=settings.db_path,
        jwt_secret=settings.jwt_secret,
        cors_origins=settings.cors_origins,
        rate_limit_per_minute=settings.rate_limit_per_minute,
        log_sources=settings.log_sources,
        narration_api_key=settings.narration_api_key,
    )

    app = create_app(settings)
    uvicorn.run(app, host=settings.host, port=settings.port, log_level="info")


if __name__ == "__main__":
    main()
