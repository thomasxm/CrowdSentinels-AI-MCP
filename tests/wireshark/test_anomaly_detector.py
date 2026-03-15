# tests/wireshark/test_anomaly_detector.py
"""Tests for anomaly detector."""
from pathlib import Path

TEST_MALWARE_DIR = Path("/home/kali/Desktop/CTU/malware_traffics")


class TestAnomalyDetector:
    """Test protocol anomaly detection."""

    def test_detect_unusual_ports(self):
        """Should detect unusual destination ports."""
        from src.wireshark.baseline.defaults import DEFAULT_BASELINE
        from src.wireshark.hunting.anomaly_detector import AnomalyDetector

        detector = AnomalyDetector(baseline=DEFAULT_BASELINE)

        # Port 4444 (Metasploit) should be flagged
        anomalies = detector.check_port_anomaly(4444, "tcp", 10)

        assert len(anomalies) > 0
        assert any("4444" in str(a) or "unusual" in str(a).lower() for a in anomalies)

    def test_detect_dns_anomalies(self):
        """Should detect DNS anomalies."""
        from src.wireshark.hunting.anomaly_detector import AnomalyDetector

        detector = AnomalyDetector()

        # Very long subdomain (potential tunnel)
        long_domain = "a" * 60 + ".evil.com"
        anomalies = detector.check_dns_anomaly(long_domain, "A", None)

        assert len(anomalies) > 0

    def test_legitimate_traffic_no_anomaly(self):
        """Should not flag legitimate traffic."""
        from src.wireshark.hunting.anomaly_detector import AnomalyDetector

        detector = AnomalyDetector()

        # Port 443 should not be flagged
        anomalies = detector.check_port_anomaly(443, "tcp", 100)

        assert len(anomalies) == 0

    def test_detect_tls_anomalies(self):
        """Should detect TLS anomalies."""
        from src.wireshark.hunting.anomaly_detector import AnomalyDetector

        detector = AnomalyDetector()

        # TLS without SNI is suspicious
        anomalies = detector.check_tls_anomaly(
            has_sni=False,
            server_ip="203.0.113.42",
            ja3_hash="abc123"
        )

        assert len(anomalies) > 0
