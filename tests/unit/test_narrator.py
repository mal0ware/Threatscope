"""Tests for the threat narrator."""

from datetime import datetime

import pytest

from agent.parsers.base import NormalizedEvent, Severity
from ml.narrator import ThreatNarrator


def _sample_events(event_type: str = "ssh_failed", count: int = 5) -> list[NormalizedEvent]:
    return [
        NormalizedEvent(
            timestamp=datetime(2026, 4, 9, 12, 0, i),
            source="auth",
            event_type=event_type,
            severity=Severity.MEDIUM,
            raw_message=f"event {i}",
            source_ip="10.0.0.1",
            dest_port=22,
        )
        for i in range(count)
    ]


class TestThreatNarrator:
    @pytest.mark.asyncio
    async def test_template_fallback(self):
        narrator = ThreatNarrator()  # no API key
        narrative = await narrator.narrate(
            _sample_events(),
            {"severity": "high", "window_minutes": 5, "attack_type": "brute force"},
        )
        assert "10.0.0.1" in narrative
        assert "5" in narrative

    @pytest.mark.asyncio
    async def test_ssh_brute_force_template(self):
        narrator = ThreatNarrator()
        narrative = await narrator.narrate(
            _sample_events("ssh_brute_force"),
            {"severity": "high", "window_minutes": 5},
        )
        assert "brute-force" in narrative.lower() or "brute" in narrative.lower()

    @pytest.mark.asyncio
    async def test_empty_events(self):
        narrator = ThreatNarrator()
        narrative = await narrator.narrate([], {})
        assert "No events" in narrative

    @pytest.mark.asyncio
    async def test_dns_template(self):
        events = [
            NormalizedEvent(
                timestamp=datetime(2026, 4, 9, 12, 0, 0),
                source="dns",
                event_type="dns_query",
                severity=Severity.MEDIUM,
                raw_message="suspicious DNS query",
                source_ip="10.0.0.1",
            )
        ]
        narrator = ThreatNarrator()
        narrative = await narrator.narrate(
            events,
            {"severity": "high", "attack_type": "DNS tunneling", "window_minutes": 10},
        )
        assert "DNS" in narrative
