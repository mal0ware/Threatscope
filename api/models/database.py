"""SQLite + FTS5 database initialization and connection management."""

from __future__ import annotations

import logging
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

__all__ = ["DatabaseManager"]

logger = logging.getLogger(__name__)

_SCHEMA = """\
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source TEXT NOT NULL CHECK(source IN ('auth', 'syslog', 'network', 'dns')),
    event_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('info', 'low', 'medium', 'high', 'critical')),
    source_ip TEXT,
    dest_ip TEXT,
    dest_port INTEGER CHECK(dest_port IS NULL OR (dest_port >= 0 AND dest_port <= 65535)),
    raw_message TEXT NOT NULL,
    anomaly_score REAL DEFAULT 0.0 CHECK(anomaly_score >= 0.0 AND anomaly_score <= 1.0),
    metadata TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_source ON events(source);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON events(event_type);

CREATE VIRTUAL TABLE IF NOT EXISTS events_fts USING fts5(
    raw_message,
    content=events,
    content_rowid=id
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_cluster TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('info', 'low', 'medium', 'high', 'critical')),
    narrative TEXT,
    acknowledged INTEGER DEFAULT 0 CHECK(acknowledged IN (0, 1)),
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_acknowledged ON alerts(acknowledged);

CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    condition_json TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('info', 'low', 'medium', 'high', 'critical')),
    enabled INTEGER DEFAULT 1 CHECK(enabled IN (0, 1)),
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
);
"""


class DatabaseManager:
    """Manages SQLite database lifecycle and provides connection access.

    Uses WAL mode for concurrent read performance and enforces foreign keys.
    Thread-safe: each call to ``connect`` returns an independent connection.
    """

    def __init__(self, db_path: Path) -> None:
        self._db_path = db_path

    def initialize(self) -> None:
        """Create database file, apply schema, and configure pragmas."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.executescript(_SCHEMA)
        logger.info("Database initialized at %s", self._db_path)

    @contextmanager
    def connect(self) -> Generator[sqlite3.Connection, None, None]:
        """Yield a configured SQLite connection with automatic cleanup."""
        conn = sqlite3.connect(str(self._db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
