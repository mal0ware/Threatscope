"""Tests for auth.log parser."""

import pytest

from agent.parsers.auth import AuthLogParser
from agent.parsers.base import Severity

_SSH_FAILED = (
    "Apr  9 14:22:01 server sshd[1234]: "
    "Failed password for admin from 192.168.1.100 port 54321 ssh2"
)
_SSH_FAILED_INVALID = (
    "Apr  9 14:22:01 server sshd[1234]: "
    "Failed password for invalid user test from 10.0.0.1 port 60000 ssh2"
)
_SSH_PUBKEY = (
    "Apr  9 14:22:01 server sshd[1234]: "
    "Accepted publickey for deploy from 10.0.0.5 port 22 ssh2"
)
_SSH_ACCEPT_PW = (
    "Apr  9 14:22:01 server sshd[5678]: "
    "Accepted password for root from 192.168.1.1 port 43210 ssh2"
)
_SUDO = (
    "Apr  9 14:22:01 server sudo: admin : "
    "TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/apt update"
)
_INVALID_USER = (
    "Apr  9 03:12:45 server sshd[9999]: "
    "Invalid user oracle from 45.33.32.156 port 51234"
)
_MAX_AUTH = (
    "Apr  9 03:12:45 server sshd[9999]: "
    "maximum authentication attempts exceeded "
    "for admin from 45.33.32.156 port 51234 ssh2"
)


@pytest.fixture
def parser():
    return AuthLogParser()


class TestSSHFailed:
    def test_extracts_fields(self, parser):
        event = parser.parse_line(_SSH_FAILED)

        assert event is not None
        assert event.event_type == "ssh_failed"
        assert event.severity == Severity.MEDIUM
        assert event.source_ip == "192.168.1.100"
        assert event.dest_port == 22
        assert event.metadata["username"] == "admin"
        assert event.metadata["port"] == 54321

    def test_invalid_user_prefix(self, parser):
        event = parser.parse_line(_SSH_FAILED_INVALID)

        assert event is not None
        assert event.event_type == "ssh_failed"
        assert event.source_ip == "10.0.0.1"


class TestSSHSuccess:
    def test_publickey(self, parser):
        event = parser.parse_line(_SSH_PUBKEY)

        assert event is not None
        assert event.event_type == "ssh_success"
        assert event.severity == Severity.INFO
        assert event.source_ip == "10.0.0.5"
        assert event.metadata["username"] == "deploy"

    def test_password(self, parser):
        event = parser.parse_line(_SSH_ACCEPT_PW)

        assert event is not None
        assert event.event_type == "ssh_success"
        assert event.metadata["username"] == "root"


class TestSudo:
    def test_command_extraction(self, parser):
        event = parser.parse_line(_SUDO)

        assert event is not None
        assert event.event_type == "sudo_command"
        assert event.severity == Severity.LOW
        assert event.metadata["username"] == "admin"
        assert "/usr/bin/apt update" in event.metadata["command"]


class TestInvalidUser:
    def test_invalid_user_attempt(self, parser):
        event = parser.parse_line(_INVALID_USER)

        assert event is not None
        assert event.event_type == "ssh_invalid_user"
        assert event.severity == Severity.MEDIUM
        assert event.source_ip == "45.33.32.156"
        assert event.metadata["username"] == "oracle"


class TestBruteForce:
    def test_max_auth_exceeded(self, parser):
        event = parser.parse_line(_MAX_AUTH)

        assert event is not None
        assert event.event_type == "ssh_brute_force"
        assert event.severity == Severity.HIGH
        assert event.source_ip == "45.33.32.156"


class TestEdgeCases:
    def test_unrecognized_line_returns_none(self, parser):
        assert parser.parse_line("some random log output") is None

    def test_empty_string_returns_none(self, parser):
        assert parser.parse_line("") is None

    def test_event_immutability(self, parser):
        event = parser.parse_line(_SSH_FAILED)
        with pytest.raises(AttributeError):
            event.severity = Severity.CRITICAL
