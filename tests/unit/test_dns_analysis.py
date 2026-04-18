"""Tests for DNS entropy analysis."""

import pytest

from ml.dns_analysis import DNSAnalysisResult, analyze_dns_query, shannon_entropy


class TestShannonEntropy:
    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_single_character(self):
        assert shannon_entropy("aaaa") == 0.0

    def test_low_entropy_normal_word(self):
        assert shannon_entropy("google") < 3.0

    def test_high_entropy_random_string(self):
        assert shannon_entropy("a1b2c3d4e5f6g7h8i9j0k1l2") > 3.5

    def test_maximum_entropy_unique_chars(self):
        # All unique characters should yield maximum entropy
        s = "abcdefghijklmnop"
        assert shannon_entropy(s) == pytest.approx(4.0)


class TestAnalyzeDNSQuery:
    def test_returns_dataclass(self):
        result = analyze_dns_query("www.google.com")
        assert isinstance(result, DNSAnalysisResult)

    def test_normal_domain_not_suspicious(self):
        result = analyze_dns_query("www.google.com")
        assert not result.suspicious
        assert not result.has_hex_encoding

    def test_tunneling_high_entropy_subdomain(self):
        result = analyze_dns_query("a1b2c3d4e5f6g7h8i9j0k1l2m3n4.evil.com")
        assert result.suspicious
        assert result.subdomain_entropy > 4.0

    def test_hex_encoded_subdomain(self):
        result = analyze_dns_query("deadbeefcafebabe1234567890abcdef.c2.example.com")
        assert result.has_hex_encoding
        assert result.suspicious

    def test_short_random_not_suspicious(self):
        # Short subdomains shouldn't trigger even with high entropy
        result = analyze_dns_query("x9k2.example.com")
        assert not result.suspicious

    def test_result_immutability(self):
        result = analyze_dns_query("test.example.com")
        with pytest.raises(AttributeError):
            result.suspicious = True
