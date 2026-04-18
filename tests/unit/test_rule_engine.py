"""Tests for the rule engine executor."""

from datetime import datetime

from agent.parsers.base import NormalizedEvent, Severity
from ml.rules.engine import RuleEngine


def _ssh_failed_event(source_ip: str = "10.0.0.1") -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=datetime(2026, 4, 9, 12, 0, 0),
        source="auth",
        event_type="ssh_failed",
        severity=Severity.MEDIUM,
        raw_message=f"Failed password for admin from {source_ip}",
        source_ip=source_ip,
        dest_port=22,
        metadata={"username": "admin"},
    )


def _network_event(
    source_ip: str = "10.0.0.1", dest_port: int = 80,
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=datetime(2026, 4, 9, 12, 0, 0),
        source="network",
        event_type="connection_attempt",
        severity=Severity.LOW,
        raw_message=f"SYN {source_ip} -> target:{dest_port}",
        source_ip=source_ip,
        dest_port=dest_port,
    )


class TestRuleEngine:
    def test_no_match_below_threshold(self):
        engine = RuleEngine()
        matches = engine.evaluate(_ssh_failed_event())
        assert len(matches) == 0

    def test_brute_force_triggers_at_threshold(self):
        engine = RuleEngine()
        all_matches = []
        for _ in range(10):
            matches = engine.evaluate(_ssh_failed_event("192.168.1.100"))
            all_matches.extend(matches)
        assert len(all_matches) == 1
        assert all_matches[0].rule.rule_id == "BRUTE_001"
        assert all_matches[0].group_key == "192.168.1.100"

    def test_different_ips_dont_aggregate(self):
        engine = RuleEngine()
        for i in range(11):
            engine.evaluate(_ssh_failed_event(f"10.0.0.{i}"))
        assert len(engine.recent_matches) == 0

    def test_alert_dict_generation(self):
        engine = RuleEngine()
        all_matches = []
        for _ in range(10):
            matches = engine.evaluate(_ssh_failed_event("10.0.0.1"))
            all_matches.extend(matches)
        assert len(all_matches) == 1
        alert = engine.to_alert_dict(all_matches[0])
        assert alert["severity"] == "high"
        assert "SSH Brute Force" in str(alert["narrative"])

    def test_network_events_tracked(self):
        engine = RuleEngine()
        # Network events should be tracked but not trigger with few events
        engine.evaluate(_network_event())
        assert len(engine.recent_matches) == 0
