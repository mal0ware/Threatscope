"""Rule engine that evaluates deterministic detection rules against sliding event windows.

Maintains per-rule sliding windows of matching events and triggers alerts
when thresholds are exceeded. Designed to run as a coroutine consuming
events from the event bus.
"""

from __future__ import annotations

import json
import logging
import time
from collections import defaultdict
from dataclasses import dataclass

from agent.parsers.base import NormalizedEvent
from ml.rules.detection import DETECTION_RULES, DetectionRule

__all__ = ["RuleEngine", "RuleMatch"]

logger = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class RuleMatch:
    """A triggered detection rule with supporting evidence."""

    rule: DetectionRule
    matched_events: tuple[NormalizedEvent, ...]
    triggered_at: float
    group_key: str


class _EventWindow:
    """Sliding time window of events grouped by a key."""

    __slots__ = ("_events",)

    def __init__(self) -> None:
        self._events: list[tuple[float, NormalizedEvent]] = []

    def add(self, event: NormalizedEvent) -> None:
        self._events.append((time.time(), event))

    def get_in_window(self, window_seconds: int) -> list[NormalizedEvent]:
        cutoff = time.time() - window_seconds
        # Prune expired events
        self._events = [(t, e) for t, e in self._events if t >= cutoff]
        return [e for _, e in self._events]


class RuleEngine:
    """Evaluates detection rules against incoming events.

    Each rule tracks events in sliding windows grouped by a key
    (typically source_ip or username). When the count of matching
    events in a window exceeds the rule's threshold, a RuleMatch
    is generated.
    """

    def __init__(self) -> None:
        # rule_id -> group_key -> EventWindow
        self._windows: dict[str, dict[str, _EventWindow]] = defaultdict(
            lambda: defaultdict(_EventWindow)
        )
        self._matches: list[RuleMatch] = []

    @property
    def recent_matches(self) -> list[RuleMatch]:
        return list(self._matches[-100:])

    def evaluate(self, event: NormalizedEvent) -> list[RuleMatch]:
        """Evaluate all rules against a new event. Returns any new matches."""
        new_matches: list[RuleMatch] = []

        for rule in DETECTION_RULES:
            if not self._event_matches_rule(event, rule):
                continue

            group_key = self._get_group_key(event, rule)
            window = self._windows[rule.rule_id][group_key]
            window.add(event)

            events_in_window = window.get_in_window(rule.window_seconds)
            if len(events_in_window) >= rule.threshold:
                match = RuleMatch(
                    rule=rule,
                    matched_events=tuple(events_in_window),
                    triggered_at=time.time(),
                    group_key=group_key,
                )
                new_matches.append(match)
                self._matches.append(match)
                # Reset window to avoid re-firing on same events
                self._windows[rule.rule_id][group_key] = _EventWindow()
                logger.warning(
                    "Rule %s triggered: %s (key=%s, events=%d)",
                    rule.rule_id,
                    rule.name,
                    group_key,
                    len(events_in_window),
                )

        return new_matches

    def to_alert_dict(self, match: RuleMatch) -> dict[str, object]:
        """Convert a RuleMatch into an alert record for database insertion."""
        event_ids = [
            e.to_dict()["timestamp"] for e in match.matched_events[:10]
        ]
        return {
            "event_cluster": json.dumps(event_ids),
            "severity": match.rule.severity.value,
            "narrative": (
                f"Rule '{match.rule.name}' triggered: "
                f"{len(match.matched_events)} matching events from "
                f"{match.group_key} within {match.rule.window_seconds}s window. "
                f"Recommended action: {match.rule.response}"
            ),
        }

    @staticmethod
    def _event_matches_rule(event: NormalizedEvent, rule: DetectionRule) -> bool:
        """Check if an event is relevant to a given rule."""
        rule_id = rule.rule_id
        if rule_id == "BRUTE_001":
            return event.event_type in ("ssh_failed", "ssh_brute_force")
        if rule_id == "PRIV_001":
            return event.event_type == "sudo_command"
        if rule_id == "SCAN_001":
            return event.source == "network"
        if rule_id == "EXFIL_001":
            return event.source == "network"
        return False

    @staticmethod
    def _get_group_key(event: NormalizedEvent, rule: DetectionRule) -> str:
        """Determine the grouping key for a rule (e.g., source IP, username)."""
        rule_id = rule.rule_id
        if rule_id in ("BRUTE_001", "SCAN_001", "EXFIL_001"):
            return event.source_ip or "unknown"
        if rule_id == "PRIV_001":
            return str(event.metadata.get("username", "unknown"))
        return "global"
