"""Tests for detection rule definitions."""

import pytest

from ml.rules.detection import DETECTION_RULES, DetectionRule, RuleSeverity


class TestDetectionRules:
    def test_all_rules_are_detection_rules(self):
        for rule in DETECTION_RULES:
            assert isinstance(rule, DetectionRule)

    def test_rule_ids_unique(self):
        ids = [rule.rule_id for rule in DETECTION_RULES]
        assert len(ids) == len(set(ids))

    def test_brute_force_rule_exists(self):
        brute = next(
            r for r in DETECTION_RULES if r.rule_id == "BRUTE_001"
        )
        assert brute.severity == RuleSeverity.HIGH
        assert brute.window_seconds == 300
        assert brute.threshold == 10

    def test_priv_esc_is_critical(self):
        priv = next(
            r for r in DETECTION_RULES if r.rule_id == "PRIV_001"
        )
        assert priv.severity == RuleSeverity.CRITICAL

    def test_all_rules_have_positive_windows(self):
        for rule in DETECTION_RULES:
            assert rule.window_seconds > 0
            assert rule.threshold > 0

    def test_rules_immutable(self):
        rule = DETECTION_RULES[0]
        with pytest.raises(AttributeError):
            rule.threshold = 999
