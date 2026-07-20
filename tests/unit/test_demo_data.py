"""Tests for the demo data generators."""

from collections import Counter
from datetime import datetime

from ml.models.dns_classifier import DNSClassifier, DNSLabel
from scripts.generate_demo_data import generate_live_events

_ALLOWED_SOURCES = {"auth", "syslog", "network", "dns"}


class TestGenerateLiveEvents:
    def test_brute_force_burst_can_trip_rule(self):
        """BRUTE_001 needs >=10 ssh_failed from one IP inside its window."""
        events = generate_live_events(now=datetime(2026, 4, 9, 12, 0, 0))
        failures = [e for e in events if e.event_type == "ssh_failed"]

        assert len(failures) >= 10
        by_ip = Counter(e.source_ip for e in failures)
        assert max(by_ip.values()) >= 10
        window = max(e.timestamp for e in failures) - min(
            e.timestamp for e in failures
        )
        assert window.total_seconds() < 300

    def test_dns_events_carry_classifier_contract(self):
        """DNS events must have the metadata shape the pipeline dispatches on."""
        events = generate_live_events()
        dns_events = [e for e in events if e.event_type == "dns_query"]

        assert dns_events
        for event in dns_events:
            assert event.source == "dns"
            assert event.metadata.get("domain")

    def test_includes_domains_the_classifier_flags(self):
        """At least one replayed domain must trip the untrained heuristics."""
        classifier = DNSClassifier()
        events = generate_live_events()
        labels = {
            classifier.classify(str(e.metadata["domain"])).label
            for e in events
            if e.event_type == "dns_query"
        }

        assert labels & {DNSLabel.TUNNELING, DNSLabel.DGA}
        assert DNSLabel.NORMAL in labels  # benign traffic stays quiet

    def test_all_sources_satisfy_schema_check_constraint(self):
        """Every replayed event must be persistable (events.source CHECK)."""
        events = generate_live_events()
        assert {e.source for e in events} <= _ALLOWED_SOURCES
