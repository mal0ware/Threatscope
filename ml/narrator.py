"""Threat narrator — translates event clusters into human-readable narratives.

Uses an external API when a key is configured, otherwise falls back to
structured template-based narratives. All core detection works without
any API key.
"""

from __future__ import annotations

import logging

from agent.parsers.base import NormalizedEvent

__all__ = ["ThreatNarrator"]

logger = logging.getLogger(__name__)


class ThreatNarrator:
    """Generates human-readable threat narratives from event clusters.

    When an API key is configured, delegates to the external narration
    service. Otherwise uses deterministic templates that cover all
    major threat categories.
    """

    def __init__(self, api_key: str = "") -> None:
        self._api_key = api_key
        self._client = None
        if api_key:
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=api_key)
                logger.info("Threat narrator initialized with API narration")
            except ImportError:
                logger.warning("anthropic package not installed, using template fallback")

    async def narrate(
        self,
        events: list[NormalizedEvent],
        anomaly_context: dict[str, object],
    ) -> str:
        """Generate a narrative for an event cluster."""
        if self._client:
            return self._api_narrate(events, anomaly_context)
        return self._template_narrate(events, anomaly_context)

    def _api_narrate(
        self,
        events: list[NormalizedEvent],
        anomaly_context: dict[str, object],
    ) -> str:
        """Generate narrative via external API."""
        event_summary = "\n".join(
            f"[{e.timestamp}] {e.severity.value.upper()} {e.event_type} "
            f"from {e.source_ip or 'local'}: {e.raw_message[:120]}"
            for e in events[:20]
        )
        context_str = "\n".join(f"{k}: {v}" for k, v in anomaly_context.items())

        try:
            response = self._client.messages.create(  # type: ignore[union-attr]
                model="claude-sonnet-4-20250514",
                max_tokens=500,
                system=(
                    "You are a security analyst. Given a cluster of security events "
                    "and anomaly detection results, provide:\n"
                    "1. A plain-English summary of what is happening\n"
                    "2. Severity assessment with reasoning\n"
                    "3. Recommended immediate actions\n"
                    "Keep responses concise and actionable. No jargon without explanation."
                ),
                messages=[{
                    "role": "user",
                    "content": f"Events:\n{event_summary}\n\nAnomaly context:\n{context_str}",
                }],
            )
            return str(response.content[0].text)  # type: ignore[union-attr]
        except Exception:
            logger.exception("API narration failed, falling back to template")
            return self._template_narrate(events, anomaly_context)

    @staticmethod
    def _template_narrate(
        events: list[NormalizedEvent],
        anomaly_context: dict[str, object],
    ) -> str:
        """Deterministic template-based narrative fallback."""
        if not events:
            return "No events to analyze."

        count = len(events)
        severity = anomaly_context.get("severity", "medium")
        attack_type = anomaly_context.get("attack_type", "suspicious activity")
        window = anomaly_context.get("window_minutes", "unknown")
        first = events[0]
        source_ip = first.source_ip or "unknown source"

        # Categorize by event type for richer templates
        event_type = first.event_type
        templates = _NARRATIVE_TEMPLATES.get(event_type, _DEFAULT_TEMPLATE)

        return templates.format(
            count=count,
            severity=severity,
            event_type=event_type,
            source_ip=source_ip,
            window=window,
            attack_type=attack_type,
            dest_port=first.dest_port or "N/A",
        )


_DEFAULT_TEMPLATE = (
    "Detected {count} {severity}-severity {event_type} events from {source_ip} "
    "over the past {window} minutes. This pattern is consistent with {attack_type}. "
    "Recommended action: review source IP activity and consider blocking if unauthorized."
)

_NARRATIVE_TEMPLATES: dict[str, str] = {
    "ssh_failed": (
        "Detected {count} failed SSH authentication attempts from {source_ip} "
        "over {window} minutes targeting port {dest_port}. "
        "This pattern is consistent with credential brute-forcing. "
        "Recommended: verify if this IP is authorized, check for compromised credentials, "
        "and consider implementing fail2ban or IP-based blocking."
    ),
    "ssh_brute_force": (
        "SSH brute-force attack detected: {count} authentication failures from "
        "{source_ip} exceeded the maximum retry threshold. "
        "Immediate action recommended: block {source_ip} at the firewall level "
        "and audit affected user accounts for compromise."
    ),
    "ssh_invalid_user": (
        "User enumeration attempt detected: {count} login attempts for non-existent "
        "usernames from {source_ip}. This is a reconnaissance technique used to "
        "discover valid accounts. Recommended: block source IP and review SSH configuration "
        "to avoid leaking valid usernames."
    ),
    "connection_attempt": (
        "Port scanning activity detected: {count} connection attempts from {source_ip} "
        "across multiple destination ports within {window} minutes. "
        "This indicates network reconnaissance. Recommended: block source IP, "
        "review firewall rules, and check for any successful connections."
    ),
    "dns_query": (
        "Suspicious DNS activity: {count} queries flagged as potential {attack_type} "
        "from {source_ip}. High-entropy subdomain patterns suggest data may be encoded "
        "in DNS requests. Recommended: inspect query patterns, block suspicious domains, "
        "and investigate the originating host for compromise."
    ),
}
