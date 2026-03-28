# tests/wireshark/test_models.py
"""Tests for Wireshark data models."""

from datetime import datetime


class TestNetworkIoC:
    """Test NetworkIoC model."""

    def test_create_ip_ioc(self):
        """Should create IP-based IoC."""
        from src.wireshark.models import NetworkIoC, PyramidLevel

        ioc = NetworkIoC(
            id="ioc-001",
            type="ip",
            value="192.168.1.100",
            pyramid_level=PyramidLevel.IP,
            confidence=8,
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            occurrence_count=5,
            source_tool="hunt_anomalies",
        )

        assert ioc.type == "ip"
        assert ioc.pyramid_level == PyramidLevel.IP
        assert ioc.confidence == 8

    def test_pyramid_level_ordering(self):
        """Pyramid levels should have correct ordering."""
        from src.wireshark.models import PyramidLevel

        assert PyramidLevel.HASH < PyramidLevel.IP
        assert PyramidLevel.IP < PyramidLevel.DOMAIN
        assert PyramidLevel.DOMAIN < PyramidLevel.ARTIFACTS
        assert PyramidLevel.ARTIFACTS < PyramidLevel.TOOLS
        assert PyramidLevel.TOOLS < PyramidLevel.TTPS


class TestPcapMetadata:
    """Test PcapMetadata model."""

    def test_create_pcap_metadata(self):
        """Should create PCAP metadata."""
        from src.wireshark.models import PcapMetadata

        metadata = PcapMetadata(
            file_path="/tmp/test.pcap",
            file_size_bytes=1024000,
            file_hash_sha256="abc123",
            packet_count=1000,
            time_start=datetime.now(),
            time_end=datetime.now(),
            duration_seconds=60.5,
            protocols_detected=["tcp", "http", "dns"],
        )

        assert metadata.packet_count == 1000
        assert "http" in metadata.protocols_detected


class TestBeaconPattern:
    """Test BeaconPattern model."""

    def test_create_beacon_pattern(self):
        """Should create beacon pattern detection."""
        from src.wireshark.models import BeaconPattern

        beacon = BeaconPattern(
            source_ip="192.168.1.100",
            dest_ip="203.0.113.42",
            dest_port=443,
            interval_mean_seconds=60.0,
            interval_stddev=2.5,
            jitter_percent=4.2,
            occurrence_count=50,
            confidence="HIGH",
            timestamps=[],
        )

        assert beacon.interval_mean_seconds == 60.0
        assert beacon.confidence == "HIGH"
