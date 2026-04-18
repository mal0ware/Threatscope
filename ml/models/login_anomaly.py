"""Login behavior anomaly detection using Isolation Forest.

Trains on a rolling baseline of normal login patterns and scores new
login events against that baseline. Features include temporal patterns,
source IP frequency, and authentication method.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime

import numpy as np
from numpy.typing import NDArray
from sklearn.ensemble import IsolationForest

__all__ = ["LoginAnomalyDetector", "LoginFeatures"]

logger = logging.getLogger(__name__)

_DEFAULT_CONTAMINATION = 0.05
_DEFAULT_N_ESTIMATORS = 100


@dataclass(frozen=True, slots=True)
class LoginFeatures:
    """Feature vector for a single login event."""

    hour_of_day: int
    day_of_week: int
    is_weekend: bool
    source_ip_hash: int
    auth_success: bool
    username_hash: int

    def to_array(self) -> NDArray[np.float64]:
        return np.array([
            self.hour_of_day,
            self.day_of_week,
            int(self.is_weekend),
            self.source_ip_hash % 1000,
            int(self.auth_success),
            self.username_hash % 1000,
        ], dtype=np.float64)


def extract_login_features(
    timestamp: datetime,
    source_ip: str | None,
    username: str | None,
    auth_success: bool,
) -> LoginFeatures:
    """Extract feature vector from a login event."""
    return LoginFeatures(
        hour_of_day=timestamp.hour,
        day_of_week=timestamp.weekday(),
        is_weekend=timestamp.weekday() >= 5,
        source_ip_hash=hash(source_ip or "unknown"),
        auth_success=auth_success,
        username_hash=hash(username or "unknown"),
    )


class LoginAnomalyDetector:
    """Isolation Forest model for login behavior anomaly detection.

    Trains on a baseline of normal login events and returns anomaly
    scores between 0.0 (normal) and 1.0 (highly anomalous).
    """

    def __init__(
        self,
        contamination: float = _DEFAULT_CONTAMINATION,
        n_estimators: int = _DEFAULT_N_ESTIMATORS,
    ) -> None:
        self._model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=42,
            n_jobs=-1,
        )
        self._is_fitted = False

    @property
    def is_fitted(self) -> bool:
        return self._is_fitted

    def train(self, features: list[LoginFeatures]) -> None:
        """Train the model on a baseline of normal login features."""
        if len(features) < 10:
            logger.warning(
                "Insufficient training data (%d samples), need at least 10",
                len(features),
            )
            return
        matrix = np.vstack([f.to_array() for f in features])
        self._model.fit(matrix)
        self._is_fitted = True
        logger.info("Login anomaly model trained on %d samples", len(features))

    def score(self, features: LoginFeatures) -> float:
        """Return anomaly score between 0.0 (normal) and 1.0 (anomalous).

        If the model is not trained, returns 0.0 (assumes normal).
        """
        if not self._is_fitted:
            return 0.0
        raw = self._model.decision_function(features.to_array().reshape(1, -1))[0]
        # Isolation Forest decision_function: negative = anomalous
        # Normalize to 0.0–1.0 where 1.0 is most anomalous
        return float(np.clip(1.0 - (raw + 0.5), 0.0, 1.0))

    def predict(self, features: LoginFeatures) -> bool:
        """Return True if the event is predicted anomalous."""
        if not self._is_fitted:
            return False
        return bool(self._model.predict(features.to_array().reshape(1, -1))[0] == -1)
