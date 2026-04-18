"""DNS entropy analysis for tunneling and DGA detection.

Uses Shannon entropy and structural heuristics to identify domains
that exhibit characteristics of DNS tunneling (C2 exfiltration) or
domain generation algorithms (botnet infrastructure).
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

__all__ = ["DNSAnalysisResult", "analyze_dns_query", "shannon_entropy"]

# Thresholds derived from empirical analysis of benign vs. malicious domains.
# See: Born et al., "A Survey on DNS Encryption" (2019)
_ENTROPY_THRESHOLD = 4.0
_SUBDOMAIN_LENGTH_THRESHOLD = 20
_HEX_PATTERN = re.compile(r"^[a-f0-9]{16,}$")
_BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")


@dataclass(frozen=True, slots=True)
class DNSAnalysisResult:
    """Result of DNS query entropy analysis."""

    domain: str
    subdomain_length: int
    subdomain_entropy: float
    has_hex_encoding: bool
    has_base64_encoding: bool
    suspicious: bool


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string (bits per character).

    Higher entropy indicates more randomness — a hallmark of encoded or
    encrypted payloads embedded in DNS queries.
    """
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum(
        (count / length) * math.log2(count / length) for count in freq.values()
    )


def analyze_dns_query(domain: str) -> DNSAnalysisResult:
    """Analyze a DNS query for tunneling / DGA indicators."""
    subdomain = domain.split(".")[0]
    entropy = shannon_entropy(subdomain)
    has_hex = bool(_HEX_PATTERN.match(subdomain))
    has_b64 = bool(_BASE64_PATTERN.match(subdomain))

    suspicious = (
        (entropy > _ENTROPY_THRESHOLD and len(subdomain) > _SUBDOMAIN_LENGTH_THRESHOLD)
        or has_hex
    )

    return DNSAnalysisResult(
        domain=domain,
        subdomain_length=len(subdomain),
        subdomain_entropy=entropy,
        has_hex_encoding=has_hex,
        has_base64_encoding=has_b64,
        suspicious=suspicious,
    )
