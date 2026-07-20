#!/usr/bin/env python3
"""Seed the database with synthetic security events for demo mode.

Generates realistic baseline traffic interspersed with simulated
attack patterns (brute force, port scan, DNS tunneling indicators)
to showcase detection capabilities without requiring live log sources.

Two flavours of demo data exist:

- :func:`seed_database` writes historical events straight to SQLite so
  the dashboard has depth (timeline, heatmap, top sources) immediately.
- :func:`generate_live_events` returns NormalizedEvents that the server
  replays through the event bus at startup, so the rule engine and DNS
  classifier fire *real* alerts instead of the alerts table starting
  empty.
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

from agent.parsers.base import NormalizedEvent, Severity
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


_NORMAL_DOMAINS = [
    "www.google.com", "api.github.com", "fonts.gstatic.com",
    "cdn.jsdelivr.net", "registry.npmjs.org", "pypi.org",
    "ubuntu.com", "debian.org", "cloudflare.com",
]
_SUSPICIOUS_DOMAINS = [
    # Hex-encoded payloads in the subdomain — classic DNS tunneling shape.
    "deadbeefcafebabe1234567890abcdef.exfil.badcorp.io",
    "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6.exfil.badcorp.io",
    # High-entropy, digit-heavy labels — DGA shape.
    "x8k2m9p4q7w1z3a5b6c0d4e7f1g5h9j2.update-cdn.net",
]


def _dns_row(ts: datetime, domain: str, client: str, qtype: str) -> tuple[object, ...]:
    return (
        ts.isoformat(),
        "dns",
        "dns_query",
        "low" if qtype in ("TXT", "NULL", "ANY") else "info",
        client,
        None,
        53,
        f"query[{qtype}] {domain} from {client}",
        0.0,
        json.dumps({"domain": domain, "query_type": qtype, "client_ip": client}),
    )


def _generate_dns_queries(base_time: datetime) -> list[tuple[object, ...]]:
    """Simulate resolver traffic: mostly benign, a few tunneling bursts."""
    events: list[tuple[object, ...]] = []
    for _ in range(40):
        ts = base_time + timedelta(seconds=random.randint(0, 5400))
        events.append(
            _dns_row(ts, random.choice(_NORMAL_DOMAINS), random.choice(_INTERNAL_IPS), "A")
        )
    compromised = random.choice(_INTERNAL_IPS)
    for i, domain in enumerate(_SUSPICIOUS_DOMAINS * 2):
        ts = base_time + timedelta(minutes=30, seconds=i * random.uniform(4, 9))
        events.append(_dns_row(ts, domain, compromised, "TXT"))
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
    all_events.extend(_generate_dns_queries(now - timedelta(hours=3)))
    all_events.extend(_generate_brute_force(now - timedelta(hours=2)))
    all_events.extend(_generate_port_scan(now - timedelta(hours=1)))
    all_events.extend(_generate_baseline(now - timedelta(hours=1), count=80))

    if db is None:
        db = DatabaseManager(_DB_PATH)
        db.initialize()

    with db.connect() as conn:
        conn.executemany(_INSERT_SQL, all_events)

    logger.info("Seeded %d demo events", len(all_events))


def generate_live_events(now: datetime | None = None) -> list[NormalizedEvent]:
    """Build a burst of NormalizedEvents to replay through the event bus.

    Replaying these at startup drives the *real* detection path (rule
    engine + DNS classifier via the ML pipeline), so demo mode produces
    genuine alerts rather than a pre-canned alerts table:

    - 12 SSH failures from one IP trip BRUTE_001 (threshold 10 in 5 min).
    - Tunneling/DGA domains trip the DNS classifier heuristics.
    - A handful of benign events show the detectors staying quiet.
    """
    now = now or datetime.now()
    attacker = random.choice(_ATTACKER_IPS)
    client = random.choice(_INTERNAL_IPS)
    events: list[NormalizedEvent] = []

    for i in range(12):
        user = random.choice(_USERNAMES)
        port = random.randint(40000, 65000)
        events.append(NormalizedEvent(
            timestamp=now - timedelta(seconds=60 - i * 5),
            source="auth",
            event_type="ssh_failed",
            severity=Severity.MEDIUM,
            raw_message=(
                f"Failed password for {user} from {attacker} port {port} ssh2"
            ),
            source_ip=attacker,
            dest_port=22,
            metadata={"username": user, "port": port},
        ))

    for domain in [*random.sample(_NORMAL_DOMAINS, 3), *_SUSPICIOUS_DOMAINS]:
        suspicious = domain in _SUSPICIOUS_DOMAINS
        qtype = "TXT" if suspicious else "A"
        events.append(NormalizedEvent(
            timestamp=now - timedelta(seconds=random.randint(5, 30)),
            source="dns",
            event_type="dns_query",
            severity=Severity.LOW if suspicious else Severity.INFO,
            raw_message=f"query[{qtype}] {domain} from {client}",
            source_ip=client,
            dest_port=53,
            metadata={"domain": domain, "query_type": qtype, "client_ip": client},
        ))

    events.append(NormalizedEvent(
        timestamp=now,
        source="auth",
        event_type="ssh_success",
        severity=Severity.INFO,
        raw_message=f"Accepted publickey for deploy from {client} port 22 ssh2",
        source_ip=client,
        dest_port=22,
        metadata={"username": "deploy", "port": 22},
    ))
    return events


if __name__ == "__main__":
    seed_database()
