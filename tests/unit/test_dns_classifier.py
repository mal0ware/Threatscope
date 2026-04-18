"""Tests for DNS tunneling/DGA classifier."""

from ml.models.dns_classifier import DNSClassifier, DNSLabel


class TestDNSClassifier:
    def test_normal_domain(self):
        classifier = DNSClassifier()
        result = classifier.classify("www.google.com")
        assert result.label == DNSLabel.NORMAL
        assert result.confidence > 0.5

    def test_hex_tunneling_detection(self):
        classifier = DNSClassifier()
        result = classifier.classify(
            "deadbeefcafebabe1234567890abcdef.c2.evil.com"
        )
        assert result.label == DNSLabel.TUNNELING
        assert result.confidence > 0.5

    def test_dga_detection(self):
        classifier = DNSClassifier()
        # High digit ratio + high entropy + long subdomain
        result = classifier.classify("x8k2m9p4q7w1z3a5b6c.botnet.ru")
        assert result.label in (DNSLabel.DGA, DNSLabel.TUNNELING)

    def test_short_domain_is_normal(self):
        classifier = DNSClassifier()
        result = classifier.classify("api.github.com")
        assert result.label == DNSLabel.NORMAL

    def test_features_populated(self):
        classifier = DNSClassifier()
        result = classifier.classify("test.example.com")
        assert "entropy" in result.features
        assert "subdomain_length" in result.features

    def test_untrained_uses_heuristics(self):
        classifier = DNSClassifier()
        assert not classifier.is_fitted
        # Should still classify (via heuristics)
        result = classifier.classify("www.example.com")
        assert result.label == DNSLabel.NORMAL
