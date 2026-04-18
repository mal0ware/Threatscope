"""Tests for network traffic anomaly detection."""

import pytest

from ml.models.network_anomaly import NetworkAnomalyDetector, TrafficSnapshot


def _normal_snapshot(**overrides: float) -> TrafficSnapshot:
    defaults = {
        "packets_per_second": 100.0,
        "bytes_per_second": 50000.0,
        "unique_dest_ips": 5,
        "unique_dest_ports": 3,
        "tcp_ratio": 0.8,
        "udp_ratio": 0.2,
    }
    defaults.update(overrides)
    return TrafficSnapshot(**defaults)  # type: ignore[arg-type]


class TestNetworkAnomalyDetector:
    def test_empty_baseline_no_flags(self):
        detector = NetworkAnomalyDetector()
        result = detector.analyze(_normal_snapshot())
        assert not result.is_anomalous
        assert result.zscore_flags == []

    def test_build_baseline_and_detect(self):
        detector = NetworkAnomalyDetector()
        for _ in range(50):
            detector.update_baseline(_normal_snapshot())
        detector.train()
        assert detector.is_fitted

        normal_result = detector.analyze(_normal_snapshot())
        assert normal_result.description  # has some description

    def test_zscore_flags_spike(self):
        detector = NetworkAnomalyDetector()
        for _ in range(50):
            detector.update_baseline(_normal_snapshot())

        # Massive spike in unique dest ports (port scan)
        spike = _normal_snapshot(unique_dest_ports=500)
        result = detector.analyze(spike)
        assert len(result.zscore_flags) > 0
        assert any("unique_dest_ports" in f for f in result.zscore_flags)

    def test_snapshot_immutable(self):
        snap = _normal_snapshot()
        with pytest.raises(AttributeError):
            snap.packets_per_second = 999.0  # type: ignore[misc]
