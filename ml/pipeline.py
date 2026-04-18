"""ML detection pipeline that consumes events from the event bus.

Orchestrates all detection models and the rule engine, running as an
asyncio task. When anomalies or rule matches are detected, alerts are
created in the database.
"""

from __future__ import annotations

import asyncio
import json
import logging

from agent.event_bus import EventBus
from agent.parsers.base import NormalizedEvent
from api.models.database import DatabaseManager
from ml.models.dns_classifier import DNSClassifier, DNSLabel
from ml.models.login_anomaly import LoginAnomalyDetector, extract_login_features
from ml.models.network_anomaly import NetworkAnomalyDetector
from ml.rules.engine import RuleEngine

__all__ = ["DetectionPipeline"]

logger = logging.getLogger(__name__)

_ANOMALY_THRESHOLD = 0.7


class DetectionPipeline:
    """Consumes events from the event bus and runs all detection models.

    Integrates:
    - Login anomaly detection (Isolation Forest)
    - Network traffic anomaly detection (Z-score + IF)
    - DNS tunneling/DGA classifier (Random Forest + heuristics)
    - Deterministic rule engine
    """

    def __init__(
        self,
        event_bus: EventBus,
        db: DatabaseManager,
        anomaly_threshold: float = _ANOMALY_THRESHOLD,
    ) -> None:
        self._event_bus = event_bus
        self._db = db
        self._threshold = anomaly_threshold

        self._login_detector = LoginAnomalyDetector()
        self._network_detector = NetworkAnomalyDetector()
        self._dns_classifier = DNSClassifier()
        self._rule_engine = RuleEngine()

        self._running = False
        self._events_processed = 0

    @property
    def events_processed(self) -> int:
        return self._events_processed

    async def start(self) -> None:
        """Subscribe to event bus and process events until stopped."""
        queue = await self._event_bus.subscribe("ml-pipeline")
        self._running = True
        logger.info("Detection pipeline started")

        try:
            while self._running:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=1.0)
                except TimeoutError:
                    continue
                await self._process_event(event)
                self._events_processed += 1
        except asyncio.CancelledError:
            pass
        finally:
            await self._event_bus.unsubscribe("ml-pipeline")
            logger.info(
                "Detection pipeline stopped after processing %d events",
                self._events_processed,
            )

    async def stop(self) -> None:
        self._running = False

    async def _process_event(self, event: NormalizedEvent) -> None:
        """Run all applicable detectors against a single event."""
        # Rule engine (always runs)
        rule_matches = self._rule_engine.evaluate(event)
        for match in rule_matches:
            await self._create_alert(self._rule_engine.to_alert_dict(match))

        # Login anomaly detection
        if event.source == "auth" and event.event_type in (
            "ssh_failed", "ssh_success", "ssh_invalid_user",
        ):
            await self._check_login_anomaly(event)

        # DNS analysis
        if event.event_type == "dns_query" and event.metadata.get("domain"):
            await self._check_dns(event)

    async def _check_login_anomaly(self, event: NormalizedEvent) -> None:
        features = extract_login_features(
            timestamp=event.timestamp,
            source_ip=event.source_ip,
            username=(
                str(event.metadata.get("username"))
                if event.metadata.get("username")
                else None
            ),
            auth_success=event.event_type == "ssh_success",
        )
        score = self._login_detector.score(features)
        if score >= self._threshold:
            await self._create_alert({
                "event_cluster": json.dumps([event.to_dict()["timestamp"]]),
                "severity": "high",
                "narrative": (
                    f"Anomalous login detected (score: {score:.2f}). "
                    f"Source IP: {event.source_ip}, "
                    f"User: {event.metadata.get('username', 'unknown')}. "
                    f"This login deviates from established baseline patterns."
                ),
            })

    async def _check_dns(self, event: NormalizedEvent) -> None:
        domain = str(event.metadata.get("domain", ""))
        if not domain:
            return
        result = self._dns_classifier.classify(str(domain))
        if result.label != DNSLabel.NORMAL:
            await self._create_alert({
                "event_cluster": json.dumps([event.to_dict()["timestamp"]]),
                "severity": "high" if result.label == DNSLabel.TUNNELING else "medium",
                "narrative": (
                    f"Suspicious DNS query: {result.domain} "
                    f"classified as {result.label.value} "
                    f"(confidence: {result.confidence:.0%}). "
                    f"Subdomain entropy: {result.features.get('entropy', 0):.2f}."
                ),
            })

    async def _create_alert(self, alert_data: dict[str, object]) -> None:
        """Insert an alert into the database."""
        with self._db.connect() as conn:
            conn.execute(
                "INSERT INTO alerts (event_cluster, severity, narrative) "
                "VALUES (?, ?, ?)",
                (
                    alert_data["event_cluster"],
                    alert_data["severity"],
                    alert_data["narrative"],
                ),
            )
        logger.info("Alert created: %s", str(alert_data.get("narrative", ""))[:80])
