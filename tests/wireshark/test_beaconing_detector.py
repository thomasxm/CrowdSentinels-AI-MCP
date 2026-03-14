# tests/wireshark/test_beaconing_detector.py
"""Tests for beaconing detector."""
import pytest
from pathlib import Path
from datetime import datetime


class TestBeaconingDetector:
    """Test C2 beaconing pattern detection."""

    def test_analyze_regular_intervals(self):
        """Should detect regular beaconing intervals."""
        from src.wireshark.hunting.beaconing_detector import BeaconingDetector

        detector = BeaconingDetector()

        # Simulated regular intervals (60s +/- 2s jitter)
        timestamps = [0, 60, 121, 180, 241, 300, 362, 420]

        result = detector.analyze_intervals(timestamps)

        assert result is not None
        assert result["mean_interval"] > 55
        assert result["mean_interval"] < 65
        assert result["jitter_percent"] < 10  # Low jitter indicates beaconing

    def test_no_beaconing_random_intervals(self):
        """Should not flag random traffic as beaconing."""
        from src.wireshark.hunting.beaconing_detector import BeaconingDetector

        detector = BeaconingDetector()

        # Random intervals - not beaconing
        timestamps = [0, 5, 150, 155, 800, 1200, 1205, 1500]

        result = detector.analyze_intervals(timestamps)

        # High jitter should indicate NOT beaconing
        assert result["jitter_percent"] > 50

    def test_detect_beaconing_pattern(self):
        """Should create BeaconPattern for regular traffic."""
        from src.wireshark.hunting.beaconing_detector import BeaconingDetector

        detector = BeaconingDetector()

        # Regular 60-second beaconing
        connections = [
            {"timestamp": 0, "src_ip": "192.168.1.100", "dst_ip": "203.0.113.42", "dst_port": 443},
            {"timestamp": 60, "src_ip": "192.168.1.100", "dst_ip": "203.0.113.42", "dst_port": 443},
            {"timestamp": 120, "src_ip": "192.168.1.100", "dst_ip": "203.0.113.42", "dst_port": 443},
            {"timestamp": 180, "src_ip": "192.168.1.100", "dst_ip": "203.0.113.42", "dst_port": 443},
            {"timestamp": 240, "src_ip": "192.168.1.100", "dst_ip": "203.0.113.42", "dst_port": 443},
            {"timestamp": 300, "src_ip": "192.168.1.100", "dst_ip": "203.0.113.42", "dst_port": 443},
        ]

        patterns = detector.detect_patterns(connections)

        assert len(patterns) > 0
        pattern = patterns[0]
        assert pattern.source_ip == "192.168.1.100"
        assert pattern.dest_ip == "203.0.113.42"
        assert pattern.interval_mean_seconds > 55
        assert pattern.interval_mean_seconds < 65

    def test_generate_ascii_timeline(self):
        """Should generate ASCII timeline visualization."""
        from src.wireshark.hunting.beaconing_detector import BeaconingDetector
        from src.wireshark.models import BeaconPattern

        detector = BeaconingDetector()

        pattern = BeaconPattern(
            source_ip="192.168.1.100",
            dest_ip="203.0.113.42",
            dest_port=443,
            interval_mean_seconds=60.0,
            interval_stddev=2.0,
            jitter_percent=3.3,
            occurrence_count=100,
            confidence="HIGH"
        )

        timeline = detector.generate_ascii_timeline(pattern)

        assert "BEACONING" in timeline
        assert "203.0.113.42" in timeline
        assert "60" in timeline or "60.0" in timeline
