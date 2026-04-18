"""Tests for syslog parser."""

import pytest

from agent.parsers.base import Severity
from agent.parsers.syslog import SyslogParser


@pytest.fixture
def parser():
    return SyslogParser()


class TestSyslogParser:
    def test_standard_syslog_line(self, parser):
        line = "Apr  9 10:30:01 webserver CRON[12345]: (root) CMD (/usr/local/bin/backup.sh)"
        event = parser.parse_line(line)

        assert event is not None
        assert event.source == "syslog"
        assert event.event_type == "syslog_CRON"
        assert event.severity == Severity.INFO
        assert event.metadata["hostname"] == "webserver"
        assert event.metadata["process"] == "CRON"

    def test_error_severity_detection(self, parser):
        line = "Apr  9 10:30:01 host kernel[0]: segfault at 0000000000000000 rip 00007f"
        event = parser.parse_line(line)

        assert event is not None
        assert event.severity == Severity.HIGH

    def test_oom_severity_detection(self, parser):
        line = "Apr  9 10:30:01 host kernel[0]: Out of memory: Killed process 1234 (java)"
        event = parser.parse_line(line)

        assert event is not None
        assert event.severity == Severity.HIGH

    def test_critical_panic(self, parser):
        line = "Apr  9 10:30:01 host kernel[0]: Kernel panic - not syncing: Fatal exception"
        event = parser.parse_line(line)

        assert event is not None
        assert event.severity == Severity.CRITICAL

    def test_malformed_line_returns_none(self, parser):
        assert parser.parse_line("not a syslog line at all") is None

    def test_empty_line_returns_none(self, parser):
        assert parser.parse_line("") is None
