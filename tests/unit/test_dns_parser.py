"""Tests for dnsmasq DNS query log parser."""

from pathlib import Path

import pytest

from agent.parsers import parser_for_path
from agent.parsers.auth import AuthLogParser
from agent.parsers.base import Severity
from agent.parsers.dns import DNSLogParser
from agent.parsers.syslog import SyslogParser

_QUERY_SYSLOG = (
    "Apr  9 14:22:01 gateway dnsmasq[817]: "
    "query[A] example.com from 192.168.1.50"
)
_QUERY_DIRECT = (
    "Apr  9 14:22:01 dnsmasq[817]: "
    "query[AAAA] fonts.gstatic.com from 10.0.0.2"
)
_QUERY_TXT = (
    "Apr  9 14:22:01 gateway dnsmasq[817]: "
    "query[TXT] deadbeefcafebabe1234567890abcdef.tunnel.evil.com from 10.0.0.7"
)
_QUERY_NUMERIC_TYPE = (
    "Apr  9 14:22:01 dnsmasq[817]: "
    "query[type=65] example.org from 192.168.1.50"
)
_QUERY_IPV6_CLIENT = (
    "Apr  9 14:22:01 dnsmasq[817]: "
    "query[A] example.net from fe80::1"
)
_FORWARDED = "Apr  9 14:22:01 dnsmasq[817]: forwarded example.com to 1.1.1.1"
_REPLY = "Apr  9 14:22:01 dnsmasq[817]: reply example.com is 93.184.216.34"
_CACHED = "Apr  9 14:22:01 dnsmasq[817]: cached example.com is 93.184.216.34"


@pytest.fixture
def parser():
    return DNSLogParser()


class TestQueryParsing:
    def test_syslog_format_extracts_fields(self, parser):
        event = parser.parse_line(_QUERY_SYSLOG)

        assert event is not None
        assert event.source == "dns"
        assert event.event_type == "dns_query"
        assert event.severity == Severity.INFO
        assert event.source_ip == "192.168.1.50"
        assert event.dest_port == 53
        assert event.metadata["domain"] == "example.com"
        assert event.metadata["query_type"] == "A"
        assert event.metadata["client_ip"] == "192.168.1.50"
        assert event.metadata["hostname"] == "gateway"

    def test_direct_log_facility_format(self, parser):
        event = parser.parse_line(_QUERY_DIRECT)

        assert event is not None
        assert event.event_type == "dns_query"
        assert event.metadata["domain"] == "fonts.gstatic.com"
        assert event.metadata["query_type"] == "AAAA"
        assert "hostname" not in event.metadata

    def test_txt_query_elevated_severity(self, parser):
        event = parser.parse_line(_QUERY_TXT)

        assert event is not None
        assert event.severity == Severity.LOW
        assert (
            event.metadata["domain"]
            == "deadbeefcafebabe1234567890abcdef.tunnel.evil.com"
        )

    def test_numeric_query_type(self, parser):
        event = parser.parse_line(_QUERY_NUMERIC_TYPE)

        assert event is not None
        assert event.metadata["query_type"] == "type=65"
        assert event.severity == Severity.INFO

    def test_ipv6_client(self, parser):
        event = parser.parse_line(_QUERY_IPV6_CLIENT)

        assert event is not None
        assert event.source_ip == "fe80::1"

    def test_domain_flows_to_classifier_contract(self, parser):
        """The ML pipeline dispatches on event_type + metadata['domain']."""
        event = parser.parse_line(_QUERY_SYSLOG)

        assert event is not None
        assert event.event_type == "dns_query"
        assert event.metadata.get("domain")


class TestNonQueryLines:
    def test_forwarded_returns_none(self, parser):
        assert parser.parse_line(_FORWARDED) is None

    def test_reply_returns_none(self, parser):
        assert parser.parse_line(_REPLY) is None

    def test_cached_returns_none(self, parser):
        assert parser.parse_line(_CACHED) is None


class TestEdgeCases:
    def test_unrecognized_line_returns_none(self, parser):
        assert parser.parse_line("some random log output") is None

    def test_empty_string_returns_none(self, parser):
        assert parser.parse_line("") is None

    def test_event_immutability(self, parser):
        event = parser.parse_line(_QUERY_SYSLOG)
        with pytest.raises(AttributeError):
            event.severity = Severity.CRITICAL


class TestParserRouting:
    def test_auth_log_routes_to_auth_parser(self):
        assert isinstance(parser_for_path(Path("/var/log/auth.log")), AuthLogParser)

    def test_rhel_secure_routes_to_auth_parser(self):
        assert isinstance(parser_for_path(Path("/var/log/secure")), AuthLogParser)

    def test_dnsmasq_log_routes_to_dns_parser(self):
        assert isinstance(parser_for_path(Path("/var/log/dnsmasq.log")), DNSLogParser)

    def test_other_logs_route_to_syslog_parser(self):
        assert isinstance(parser_for_path(Path("/var/log/syslog")), SyslogParser)
