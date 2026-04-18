"""Parser for /var/log/syslog — system events, service crashes."""

from __future__ import annotations

import re
from datetime import datetime

from .base import LogParser, NormalizedEvent, Severity

__all__ = ["SyslogParser"]

_SEVERITY_MAP: dict[str, Severity] = {
    "error": Severity.MEDIUM,
    "fail": Severity.MEDIUM,
    "critical": Severity.HIGH,
    "panic": Severity.CRITICAL,
    "segfault": Severity.HIGH,
    "oom-killer": Severity.HIGH,
    "killed process": Severity.HIGH,
    "out of memory": Severity.HIGH,
}


class SyslogParser(LogParser):
    """Parses RFC 3164 / standard syslog format entries.

    Extracts timestamp, hostname, process name, and message body.
    Severity is inferred from keyword matching against the message content.
    """

    _LINE_RE = re.compile(
        r"(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+(\S+?)(?:\[\d+\])?:\s+(.*)"
    )

    @staticmethod
    def _parse_timestamp(ts_str: str) -> datetime:
        year = datetime.now().year
        return datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")

    @staticmethod
    def _classify_severity(message: str) -> Severity:
        lower = message.lower()
        for keyword, severity in _SEVERITY_MAP.items():
            if keyword in lower:
                return severity
        return Severity.INFO

    def parse_line(self, line: str) -> NormalizedEvent | None:
        m = self._LINE_RE.match(line)
        if not m:
            return None

        ts_str, hostname, process, message = m.groups()
        return NormalizedEvent(
            timestamp=self._parse_timestamp(ts_str),
            source="syslog",
            event_type=f"syslog_{process}",
            severity=self._classify_severity(message),
            raw_message=line.strip(),
            metadata={"hostname": hostname, "process": process},
        )
