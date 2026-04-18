"""Network traffic anomaly detection using rolling Z-score + Isolation Forest.

Maintains a rolling statistical baseline of network traffic metrics and
flags deviations beyond configurable thresholds. Combines Z-score for
single-feature outliers with Isolation Forest for multi-feature anomalies.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import numpy as np
from numpy.typing import NDArray
from sklearn.ensemble import IsolationForest

__all__ = ["NetworkAnomalyDetector", "TrafficSnapshot"]

logger = logging.getLogger(__name__)

_ZSCORE_THRESHOLD = 3.0
_MIN_BASELINE_SAMPLES = 30


@dataclass(frozen=True, slots=True)
class TrafficSnapshot:
    """Point-in-time network traffic metrics."""

    packets_per_second: float
    bytes_per_second: float
    unique_dest_ips: int
    unique_dest_ports: int
    tcp_ratio: float
    udp_ratio: float

    def to_array(self) -> NDArray[np.float64]:
        return np.array([
            self.packets_per_second,
            self.bytes_per_second,
            self.unique_dest_ips,
            self.unique_dest_ports,
            self.tcp_ratio,
            self.udp_ratio,
        ], dtype=np.float64)


@dataclass
class AnomalyResult:
    """Result of network traffic anomaly analysis."""

    is_anomalous: bool
    anomaly_score: float
    zscore_flags: list[str]
    description: str


class NetworkAnomalyDetector:
    """Hybrid Z-score + Isolation Forest network anomaly detector.

    The Z-score layer catches single-feature outliers (e.g., sudden port
    scan). The Isolation Forest catches multi-feature anomalies that no
    single metric would flag alone (e.g., slow exfiltration with unusual
    protocol mix).
    """

    def __init__(self, zscore_threshold: float = _ZSCORE_THRESHOLD) -> None:
        self._baseline: list[NDArray[np.float64]] = []
        self._zscore_threshold = zscore_threshold
        self._model = IsolationForest(
            contamination=0.05,
            n_estimators=100,
            random_state=42,
            n_jobs=-1,
        )
        self._is_fitted = False

    @property
    def baseline_size(self) -> int:
        return len(self._baseline)

    @property
    def is_fitted(self) -> bool:
        return self._is_fitted

    def update_baseline(self, snapshot: TrafficSnapshot) -> None:
        """Add a traffic snapshot to the rolling baseline."""
        self._baseline.append(snapshot.to_array())

    def train(self) -> None:
        """Fit the Isolation Forest on the accumulated baseline."""
        if len(self._baseline) < _MIN_BASELINE_SAMPLES:
            logger.warning(
                "Insufficient baseline data (%d/%d), skipping training",
                len(self._baseline),
                _MIN_BASELINE_SAMPLES,
            )
            return
        matrix = np.vstack(self._baseline)
        self._model.fit(matrix)
        self._is_fitted = True
        logger.info("Network anomaly model trained on %d snapshots", len(self._baseline))

    def analyze(self, snapshot: TrafficSnapshot) -> AnomalyResult:
        """Analyze a traffic snapshot for anomalies."""
        arr = snapshot.to_array()
        zscore_flags = self._check_zscores(arr)

        if_score = 0.0
        if self._is_fitted:
            raw = self._model.decision_function(arr.reshape(1, -1))[0]
            if_score = float(np.clip(1.0 - (raw + 0.5), 0.0, 1.0))

        # Combine: Z-score flags or high IF score triggers anomaly
        combined_score = max(
            if_score,
            min(1.0, len(zscore_flags) * 0.3),
        )
        is_anomalous = bool(combined_score > 0.5 or len(zscore_flags) >= 2)

        description = self._build_description(zscore_flags, if_score)

        return AnomalyResult(
            is_anomalous=is_anomalous,
            anomaly_score=combined_score,
            zscore_flags=zscore_flags,
            description=description,
        )

    def _check_zscores(self, arr: NDArray[np.float64]) -> list[str]:
        """Check each feature against baseline Z-scores."""
        if len(self._baseline) < _MIN_BASELINE_SAMPLES:
            return []

        matrix = np.vstack(self._baseline)
        means = matrix.mean(axis=0)
        stds = matrix.std(axis=0)
        stds[stds == 0] = 1.0  # avoid division by zero

        feature_names = [
            "packets_per_second",
            "bytes_per_second",
            "unique_dest_ips",
            "unique_dest_ports",
            "tcp_ratio",
            "udp_ratio",
        ]

        flags = []
        zscores = np.abs((arr - means) / stds)
        for name, zscore in zip(feature_names, zscores, strict=True):
            if zscore > self._zscore_threshold:
                flags.append(f"{name} ({zscore:.1f}σ)")

        return flags

    @staticmethod
    def _build_description(zscore_flags: list[str], if_score: float) -> str:
        parts = []
        if zscore_flags:
            parts.append(f"Statistical outliers: {', '.join(zscore_flags)}")
        if if_score > 0.5:
            parts.append(f"Multi-feature anomaly score: {if_score:.2f}")
        return "; ".join(parts) if parts else "Normal traffic pattern"
