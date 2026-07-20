"""Log parsers for various formats."""

from pathlib import Path

from agent.parsers.auth import AuthLogParser
from agent.parsers.base import LogParser, NormalizedEvent
from agent.parsers.dns import DNSLogParser
from agent.parsers.syslog import SyslogParser

__all__ = [
    "AuthLogParser",
    "DNSLogParser",
    "LogParser",
    "NormalizedEvent",
    "SyslogParser",
    "parser_for_path",
]


def parser_for_path(path: Path) -> LogParser:
    """Choose the appropriate parser for a log file based on its name.

    - ``auth`` / ``secure`` (Debian auth.log, RHEL secure) -> AuthLogParser
    - ``dns`` (dnsmasq.log, dns.log)                       -> DNSLogParser
    - anything else                                        -> SyslogParser
    """
    name = path.name.lower()
    if "auth" in name or "secure" in name:
        return AuthLogParser()
    if "dns" in name:
        return DNSLogParser()
    return SyslogParser()
