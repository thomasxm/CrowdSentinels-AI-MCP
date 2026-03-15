# tests/wireshark/test_baseline_defaults.py
"""Tests for baseline defaults."""


class TestBaselineDefaults:
    """Test prebuilt baseline defaults."""

    def test_default_baseline_has_legitimate_ports(self):
        """Default baseline should have legitimate ports."""
        from src.wireshark.baseline.defaults import DEFAULT_BASELINE

        assert "legitimate_ports" in DEFAULT_BASELINE
        assert "tcp" in DEFAULT_BASELINE["legitimate_ports"]
        assert "udp" in DEFAULT_BASELINE["legitimate_ports"]
        assert 443 in DEFAULT_BASELINE["legitimate_ports"]["tcp"]
        assert 53 in DEFAULT_BASELINE["legitimate_ports"]["udp"]

    def test_default_baseline_has_internal_ranges(self):
        """Default baseline should have internal IP ranges."""
        from src.wireshark.baseline.defaults import DEFAULT_BASELINE

        assert "internal_ranges" in DEFAULT_BASELINE
        assert "10.0.0.0/8" in DEFAULT_BASELINE["internal_ranges"]
        assert "192.168.0.0/16" in DEFAULT_BASELINE["internal_ranges"]

    def test_default_baseline_has_thresholds(self):
        """Default baseline should have detection thresholds."""
        from src.wireshark.baseline.defaults import DEFAULT_BASELINE

        thresholds = DEFAULT_BASELINE["threshold_settings"]
        assert thresholds["dns_query_length_max"] > 0
        assert thresholds["beacon_interval_tolerance"] > 0
        assert thresholds["min_beacon_count"] > 0

    def test_is_internal_ip(self):
        """Should correctly identify internal IPs."""
        from src.wireshark.baseline.defaults import is_internal_ip

        assert is_internal_ip("192.168.1.1") is True
        assert is_internal_ip("10.0.0.1") is True
        assert is_internal_ip("172.16.0.1") is True
        assert is_internal_ip("8.8.8.8") is False
        assert is_internal_ip("203.0.113.1") is False

    def test_is_legitimate_port(self):
        """Should identify legitimate ports."""
        from src.wireshark.baseline.defaults import DEFAULT_BASELINE, is_legitimate_port

        assert is_legitimate_port(443, "tcp", DEFAULT_BASELINE) is True
        assert is_legitimate_port(80, "tcp", DEFAULT_BASELINE) is True
        assert is_legitimate_port(53, "udp", DEFAULT_BASELINE) is True
        assert is_legitimate_port(31337, "tcp", DEFAULT_BASELINE) is False
