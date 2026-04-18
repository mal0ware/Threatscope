"""Base classes and schemas for log parsing."""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

__all__ = ["LogParser", "NormalizedEvent", "Severity"]


class Severity(Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True, slots=True)
class NormalizedEvent:
    """Normalized security event schema.

    All log parsers emit this common structure regardless of source format.
    Immutable by design to prevent downstream mutation of event data.
    """

    timestamp: datetime
    source: str
    event_type: str
    severity: Severity
    raw_message: str
    source_ip: str | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    metadata: dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "event_type": self.event_type,
            "severity": self.severity.value,
            "raw_message": self.raw_message,
            "source_ip": self.source_ip,
            "dest_ip": self.dest_ip,
            "dest_port": self.dest_port,
            "metadata": self.metadata,
        }


class LogParser(abc.ABC):
    """Abstract base class for log source parsers."""

    @abc.abstractmethod
    def parse_line(self, line: str) -> NormalizedEvent | None:
        """Parse a single log line into a NormalizedEvent.

        Returns None if the line does not match any known pattern.
        """
