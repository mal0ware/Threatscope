"""Tests for login anomaly detection."""

from datetime import datetime

from ml.models.login_anomaly import (
    LoginAnomalyDetector,
    extract_login_features,
)


class TestLoginFeatures:
    def test_extract_from_event(self):
        features = extract_login_features(
            timestamp=datetime(2026, 4, 9, 14, 30),
            source_ip="10.0.0.1",
            username="admin",
            auth_success=False,
        )
        assert features.hour_of_day == 14
        assert features.day_of_week == 3  # Thursday
        assert not features.is_weekend
        assert not features.auth_success

    def test_weekend_detection(self):
        features = extract_login_features(
            timestamp=datetime(2026, 4, 11, 3, 0),  # Saturday
            source_ip="10.0.0.1",
            username="admin",
            auth_success=True,
        )
        assert features.is_weekend

    def test_to_array_shape(self):
        features = extract_login_features(
            timestamp=datetime(2026, 4, 9, 12, 0),
            source_ip="10.0.0.1",
            username="root",
            auth_success=True,
        )
        arr = features.to_array()
        assert arr.shape == (6,)


class TestLoginAnomalyDetector:
    def test_untrained_returns_zero(self):
        detector = LoginAnomalyDetector()
        features = extract_login_features(
            datetime(2026, 4, 9, 12, 0), "10.0.0.1", "admin", True,
        )
        assert detector.score(features) == 0.0
        assert not detector.predict(features)

    def test_train_and_score(self):
        detector = LoginAnomalyDetector()
        # Build baseline of weekday, business-hours logins
        baseline = [
            extract_login_features(
                datetime(2026, 4, 7, h, 0), "10.0.0.1", "admin", True,
            )
            for h in range(9, 18)
            for _ in range(5)
        ]
        detector.train(baseline)
        assert detector.is_fitted

        # Normal login should score low
        normal = extract_login_features(
            datetime(2026, 4, 8, 10, 0), "10.0.0.1", "admin", True,
        )
        assert detector.score(normal) < 0.8

    def test_insufficient_data_skips_training(self):
        detector = LoginAnomalyDetector()
        detector.train([
            extract_login_features(
                datetime(2026, 4, 9, 12, 0), "10.0.0.1", "admin", True,
            )
        ])
        assert not detector.is_fitted
