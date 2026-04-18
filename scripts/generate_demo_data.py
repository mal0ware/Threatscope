#!/usr/bin/env python3
"""Seed the database with synthetic security events for demo mode.

Generates realistic baseline traffic interspersed with simulated
attack patterns (brute force, port scan, DNS tunneling indicators)
to showcase detection capabilities without requiring live log sources.
"""

from __future__ import annotations

import json
import logging
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Ensure project root is importable when run as a script.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api.models.database import DatabaseManager

logger = logging.getLogger(__name__)

_DB_PATH = Path(__file__).resolve().parent.parent / "data" / "threatscope.db"

# Realistic IP ranges
_INTERNAL_IPS = ["10.0.0.2", "10.0.0.5", "10.0.0.10", "10.0.0.25", "192.168.1.50"]
_ATTACKER_IPS = ["45.33.32.156", "185.220.101.1", "23.129.64.100", "91.240.118.172"]
_USERNAMES = ["admin", "deploy", "root", "www-data", "backup", "jenkins", "git"]

_INSERT_SQL = """\
    INSERT INTO events (timestamp, source, event_type, severity,
        source_ip, dest_ip, dest_port, raw_message, anomaly_score, metadata)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def _generate_brute_force(base_time: datetime) -> list[tuple[object, ...]]:
    """Simulate SSH brute-force attack from a single source IP."""
    attacker = random.choice(_ATTACKER_IPS)
    count = random.randint(15, 50)
    events: list[tuple[object, ...]] = []
    for i in range(count):
        user = random.choice(_USERNAMES)
        port = random.randint(40000, 65000)
        ts = base_time + timedelta(seconds=i * random.uniform(1.5, 3.0))
        events.append((
            ts.isoformat(),
            "auth",
            "ssh_failed",
            "medium",
            attacker,
            None,
            22,
            f"Failed password for {user} from {attacker} port {port} ssh2",
            0.0,
            json.dumps({"username": user, "port": port}),
        ))
    return events


def _generate_port_scan(base_time: datetime) -> list[tuple[object, ...]]:
    """Simulate sequential SYN port scan."""
    scanner = random.choice(_ATTACKER_IPS)
    target = random.choice(_INTERNAL_IPS)
    ports = random.sample(range(1, 1024), 80)
    events: list[tuple[object, ...]] = []
    for i, port in enumerate(sorted(ports)):
        ts = base_time + timedelta(milliseconds=i * random.uniform(30, 80))
        events.append((
            ts.isoformat(),
            "network",
            "connection_attempt",
            "low",
            scanner,
            target,
            port,
            f"SYN {scanner}:{random.randint(40000, 65000)} -> {target}:{port}",
            0.0,
            json.dumps({"protocol": "tcp", "flags": "SYN"}),
        ))
    return events


def _generate_baseline(base_time: datetime, count: int = 200) -> list[tuple[object, ...]]:
    """Simulate normal background traffic."""
    event_templates = [
        ("auth", "ssh_success", "info", 22),
        ("syslog", "syslog_cron", "info", None),
        ("syslog", "syslog_systemd", "info", None),
        ("network", "dns_query", "info", 53),
        ("network", "https_connection", "info", 443),
    ]
    events: list[tuple[object, ...]] = []
    for _ in range(count):
        ts = base_time + timedelta(seconds=random.randint(0, 3600))
        ip = random.choice(_INTERNAL_IPS)
        source, event_type, severity, port = random.choice(event_templates)
        events.append((
            ts.isoformat(),
            source,
            event_type,
            severity,
            ip,
            None,
            port,
            f"{event_type} from {ip}",
            0.0,
            json.dumps({}),
        ))
    return events


def seed_database(db: DatabaseManager | None = None) -> None:
    """Generate and insert demo events into the database.

    Args:
        db: Optional pre-configured DatabaseManager. If ``None``, a default
            instance is created using the standard data directory.
    """
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    now = datetime.now()

    all_events: list[tuple[object, ...]] = []
    all_events.extend(_generate_baseline(now - timedelta(hours=6)))
    all_events.extend(_generate_brute_force(now - timedelta(hours=2)))
    all_events.extend(_generate_port_scan(now - timedelta(hours=1)))
    all_events.extend(_generate_baseline(now - timedelta(hours=1), count=80))

    if db is None:
        db = DatabaseManager(_DB_PATH)
        db.initialize()

    with db.connect() as conn:
        conn.executemany(_INSERT_SQL, all_events)

    logger.info("Seeded %d demo events", len(all_events))


if __name__ == "__main__":
    seed_database()
