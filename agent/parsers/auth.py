"""Parser for /var/log/auth.log — SSH, sudo, PAM events."""

from __future__ import annotations

import re
from datetime import datetime

from .base import LogParser, NormalizedEvent, Severity

__all__ = ["AuthLogParser"]

_TIMESTAMP_RE = r"(\w+\s+\d+\s+[\d:]+)"
_HOST_RE = r"\S+"
_SSHD_RE = rf"{_TIMESTAMP_RE}\s+{_HOST_RE}\s+sshd\[\d+\]:\s+"


class AuthLogParser(LogParser):
    """Parses /var/log/auth.log for SSH, sudo, and PAM events.

    Supports detection of:
    - Failed/successful SSH authentication
    - sudo command execution
    - Brute-force threshold violations
    - Invalid user enumeration attempts
    """

    _SSH_FAILED = re.compile(
        _SSHD_RE + r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)"
    )
    _SSH_SUCCESS = re.compile(
        _SSHD_RE + r"Accepted (?:password|publickey) for (\S+) from ([\d.]+) port (\d+)"
    )
    _SSH_INVALID_USER = re.compile(
        _SSHD_RE + r"Invalid user (\S+) from ([\d.]+) port (\d+)"
    )
    _SUDO_CMD = re.compile(
        rf"{_TIMESTAMP_RE}\s+{_HOST_RE}\s+sudo:\s+(\S+)\s+:.*COMMAND=(.*)"
    )
    _SSH_MAX_AUTH = re.compile(
        _SSHD_RE
        + r"maximum authentication attempts exceeded for (?:invalid user )?(\S+) from ([\d.]+)"
    )

    @staticmethod
    def _parse_timestamp(ts_str: str) -> datetime:
        year = datetime.now().year
        return datetime.strptime(f"{year} {ts_str}", "%Y %b %d %H:%M:%S")

    def parse_line(self, line: str) -> NormalizedEvent | None:
        if m := self._SSH_FAILED.search(line):
            return NormalizedEvent(
                timestamp=self._parse_timestamp(m.group(1)),
                source="auth",
                event_type="ssh_failed",
                severity=Severity.MEDIUM,
                raw_message=line.strip(),
                source_ip=m.group(3),
                dest_port=22,
                metadata={"username": m.group(2), "port": int(m.group(4))},
            )

        if m := self._SSH_SUCCESS.search(line):
            return NormalizedEvent(
                timestamp=self._parse_timestamp(m.group(1)),
                source="auth",
                event_type="ssh_success",
                severity=Severity.INFO,
                raw_message=line.strip(),
                source_ip=m.group(3),
                dest_port=22,
                metadata={"username": m.group(2), "port": int(m.group(4))},
            )

        if m := self._SSH_INVALID_USER.search(line):
            return NormalizedEvent(
                timestamp=self._parse_timestamp(m.group(1)),
                source="auth",
                event_type="ssh_invalid_user",
                severity=Severity.MEDIUM,
                raw_message=line.strip(),
                source_ip=m.group(3),
                dest_port=22,
                metadata={"username": m.group(2), "port": int(m.group(4))},
            )

        if m := self._SUDO_CMD.search(line):
            return NormalizedEvent(
                timestamp=self._parse_timestamp(m.group(1)),
                source="auth",
                event_type="sudo_command",
                severity=Severity.LOW,
                raw_message=line.strip(),
                metadata={"username": m.group(2), "command": m.group(3).strip()},
            )

        if m := self._SSH_MAX_AUTH.search(line):
            return NormalizedEvent(
                timestamp=self._parse_timestamp(m.group(1)),
                source="auth",
                event_type="ssh_brute_force",
                severity=Severity.HIGH,
                raw_message=line.strip(),
                source_ip=m.group(3),
                dest_port=22,
                metadata={"username": m.group(2)},
            )

        return None
