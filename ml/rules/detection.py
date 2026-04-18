"""Deterministic detection rules for known attack patterns.

Rules complement ML-based anomaly detection by catching well-known attack
signatures with zero false-positive tolerance. Each rule defines a
condition evaluated against sliding event windows.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

__all__ = ["DetectionRule", "RuleSeverity", "DETECTION_RULES"]


class RuleSeverity(Enum):
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class DetectionRule:
    """A deterministic detection rule definition."""

    rule_id: str
    name: str
    condition: str
    severity: RuleSeverity
    response: str
    window_seconds: int
    threshold: int


DETECTION_RULES: tuple[DetectionRule, ...] = (
    DetectionRule(
        rule_id="BRUTE_001",
        name="SSH Brute Force",
        condition="count(ssh_failed) from same source_ip",
        severity=RuleSeverity.HIGH,
        response="flag + auto-block suggestion",
        window_seconds=300,
        threshold=10,
    ),
    DetectionRule(
        rule_id="PRIV_001",
        name="Privilege Escalation Attempt",
        condition="sudo failure followed by sudo success from same user",
        severity=RuleSeverity.CRITICAL,
        response="immediate alert",
        window_seconds=120,
        threshold=1,
    ),
    DetectionRule(
        rule_id="SCAN_001",
        name="Port Scan Detection",
        condition="unique dest_ports from same source_ip",
        severity=RuleSeverity.MEDIUM,
        response="flag + network context",
        window_seconds=60,
        threshold=50,
    ),
    DetectionRule(
        rule_id="EXFIL_001",
        name="Data Exfiltration Indicator",
        condition="outbound_bytes > 3 stddev above baseline for host",
        severity=RuleSeverity.HIGH,
        response="alert + traffic breakdown",
        window_seconds=600,
        threshold=3,
    ),
)
