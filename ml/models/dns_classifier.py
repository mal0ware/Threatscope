"""DNS tunneling and DGA classifier.

Combines entropy-based heuristics with a trained Random Forest classifier
to detect DNS tunneling (C2 exfiltration) and domain generation algorithms
(botnet infrastructure).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from enum import Enum

import numpy as np
from numpy.typing import NDArray
from sklearn.ensemble import RandomForestClassifier

from ml.dns_analysis import shannon_entropy

__all__ = ["DNSClassifier", "DNSLabel", "DNSClassification"]

logger = logging.getLogger(__name__)

_HEX_RE = re.compile(r"^[a-f0-9]{16,}$")
_DIGIT_RE = re.compile(r"\d")
_CONSONANT_RE = re.compile(r"[bcdfghjklmnpqrstvwxyz]", re.IGNORECASE)


class DNSLabel(Enum):
    NORMAL = "normal"
    TUNNELING = "tunneling_suspect"
    DGA = "dga_suspect"


@dataclass(frozen=True, slots=True)
class DNSClassification:
    """Result of DNS query classification."""

    domain: str
    label: DNSLabel
    confidence: float
    features: dict[str, float]


def _extract_features(domain: str) -> NDArray[np.float64]:
    """Extract numeric features from a domain for classification."""
    parts = domain.split(".")
    subdomain = parts[0] if parts else ""
    full_no_tld = ".".join(parts[:-1]) if len(parts) > 1 else domain

    entropy = shannon_entropy(subdomain)
    length = len(subdomain)
    digit_ratio = len(_DIGIT_RE.findall(subdomain)) / max(length, 1)
    consonant_ratio = len(_CONSONANT_RE.findall(subdomain)) / max(length, 1)
    has_hex = float(bool(_HEX_RE.match(subdomain)))
    dot_count = full_no_tld.count(".")
    max_label_len = max((len(p) for p in parts[:-1]), default=0)
    total_length = len(domain)

    return np.array([
        entropy,
        length,
        digit_ratio,
        consonant_ratio,
        has_hex,
        dot_count,
        max_label_len,
        total_length,
    ], dtype=np.float64)


def _features_to_dict(arr: NDArray[np.float64]) -> dict[str, float]:
    names = [
        "entropy", "subdomain_length", "digit_ratio", "consonant_ratio",
        "has_hex", "dot_count", "max_label_length", "total_length",
    ]
    return {name: float(val) for name, val in zip(names, arr, strict=True)}


class DNSClassifier:
    """Random Forest classifier for DNS tunneling / DGA detection.

    Falls back to heuristic rules when no training data is available.
    The heuristic layer alone catches the most obvious cases (high
    entropy + long subdomains + hex patterns).
    """

    def __init__(self) -> None:
        self._model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1,
        )
        self._is_fitted = False

    @property
    def is_fitted(self) -> bool:
        return self._is_fitted

    def train(
        self,
        domains: list[str],
        labels: list[DNSLabel],
    ) -> None:
        """Train on labeled domain examples."""
        if len(domains) < 20:
            logger.warning("Insufficient training data (%d), need 20+", len(domains))
            return
        matrix = np.vstack([_extract_features(d) for d in domains])
        label_ints = [label.value for label in labels]
        self._model.fit(matrix, label_ints)
        self._is_fitted = True
        logger.info("DNS classifier trained on %d domains", len(domains))

    def classify(self, domain: str) -> DNSClassification:
        """Classify a DNS query as normal, tunneling, or DGA."""
        features = _extract_features(domain)
        feature_dict = _features_to_dict(features)

        if self._is_fitted:
            proba = self._model.predict_proba(features.reshape(1, -1))[0]
            classes = list(self._model.classes_)
            best_idx = int(np.argmax(proba))
            label = DNSLabel(classes[best_idx])
            confidence = float(proba[best_idx])
        else:
            label, confidence = self._heuristic_classify(features)

        return DNSClassification(
            domain=domain,
            label=label,
            confidence=confidence,
            features=feature_dict,
        )

    @staticmethod
    def _heuristic_classify(
        features: NDArray[np.float64],
    ) -> tuple[DNSLabel, float]:
        """Fallback heuristic classification when model is untrained."""
        entropy = features[0]
        length = features[1]
        digit_ratio = features[2]
        has_hex = features[4]

        # High entropy + long subdomain + hex = tunneling
        if has_hex > 0.5 and length > 16:
            return DNSLabel.TUNNELING, 0.85

        # High entropy + high digit ratio + moderate length = DGA
        if entropy > 3.8 and digit_ratio > 0.4 and length > 12:
            return DNSLabel.DGA, 0.70

        # High entropy + long subdomain = tunneling suspect
        if entropy > 4.0 and length > 20:
            return DNSLabel.TUNNELING, 0.65

        return DNSLabel.NORMAL, 0.90
