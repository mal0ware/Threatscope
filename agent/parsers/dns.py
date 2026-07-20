"""Parser for dnsmasq query logs — DNS queries with client attribution.

dnsmasq writes one line per query when started with ``log-queries``.
Two line shapes exist depending on where the log is written:

- Via syslog (hostname present)::

    Apr  9 14:22:01 gateway dnsmasq[817]: query[A] example.com from 192.168.1.50

- Direct to a file with ``log-facility=/var/log/dnsmasq.log`` (no hostname)::

    Apr  9 14:22:01 dnsmasq[817]: query[AAAA] fonts.gstatic.com from 10.0.0.2

Both shapes are handled. Non-query operational lines (``forwarded``,
``reply``, ``cached``, ``config``) are ignored — only client-attributed
queries become events, which is what the DNS tunneling/DGA classifier
consumes downstream.

To point ThreatScope at a dnsmasq log, add to /etc/dnsmasq.conf::

    log-queries
    log-facility=/var/log/dnsmasq.log

then include the file in ``THREATSCOPE_LOG_SOURCES`` (it is part of the
default source list).
"""

from __future__ import annotations

import re
from datetime import datetime

from .base import LogParser, NormalizedEvent, Severity

__all__ = ["DNSLogParser"]

# Record types with large payload capacity — the classic DNS tunneling
# carriers. Queries for these are worth a slightly elevated severity so
# they stand out in the dashboard even before classification.
_TUNNEL_CAPABLE_TYPES = frozenset({"TXT", "NULL", "ANY"})


class DNSLogParser(LogParser):
    """Parses dnsmasq ``log-queries`` output into normalized DNS events.

    Emits ``dns_query`` events carrying the queried domain, record type,
    and requesting client IP in metadata — the exact shape the ML
    pipeline's DNS classifier subscribes to.
    """

    # Timestamp, optional syslog hostname, then "dnsmasq[pid]: query[TYPE] domain from client".
    # The hostname group is optional so both syslog-routed and direct
    # log-facility files parse with the same expression.
    _QUERY_RE = re.compile(
        r"(\w+\s+\d+\s+[\d:]+)\s+(?:(\S+)\s+)?dnsmasq\[\d+\]:\s+"
        r"query\[([^\]]+)\]\s+(\S+)\s+from\s+(\S+)"
    )

    @staticmethod
    def _parse_timestamp(ts_str: str) -> datetime:
        year = datetime.now().year
        return datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")

    def parse_line(self, line: str) -> NormalizedEvent | None:
        m = self._QUERY_RE.search(line)
        if not m:
            return None

        ts_str, hostname, query_type, domain, client_ip = m.groups()
        severity = (
            Severity.LOW
            if query_type.upper() in _TUNNEL_CAPABLE_TYPES
            else Severity.INFO
        )

        metadata: dict[str, object] = {
            "domain": domain,
            "query_type": query_type,
            "client_ip": client_ip,
        }
        if hostname:
            metadata["hostname"] = hostname

        return NormalizedEvent(
            timestamp=self._parse_timestamp(ts_str),
            source="dns",
            event_type="dns_query",
            severity=severity,
            raw_message=line.strip(),
            source_ip=client_ip,
            dest_port=53,
            metadata=metadata,
        )
