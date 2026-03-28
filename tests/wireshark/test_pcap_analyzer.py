# tests/wireshark/test_pcap_analyzer.py
"""Tests for PCAP analyzer."""

from pathlib import Path

import pytest

# Use a small test pcap if available, otherwise mock
TEST_PCAP_DIR = Path("/home/kali/Desktop/CTU/normal_traffics")


class TestPcapAnalyzer:
    """Test PCAP file analysis."""

    def test_validate_pcap_file_exists(self):
        """Should validate pcap file exists."""
        from src.wireshark.core.pcap_analyzer import PcapAnalyzer

        analyzer = PcapAnalyzer()

        # Non-existent file should raise
        with pytest.raises(FileNotFoundError):
            analyzer.validate_pcap("/nonexistent/file.pcap")

    def test_get_pcap_metadata(self):
        """Should extract pcap metadata."""
        from src.wireshark.core.pcap_analyzer import PcapAnalyzer

        analyzer = PcapAnalyzer()

        # Find a test pcap
        pcap_files = list(TEST_PCAP_DIR.glob("**/*.pcap"))
        if not pcap_files:
            pytest.skip("No test pcap files available")

        test_pcap = str(pcap_files[0])
        metadata = analyzer.get_metadata(test_pcap)

        assert metadata is not None
        assert metadata.file_path == test_pcap
        assert metadata.packet_count >= 0

    def test_get_protocol_hierarchy(self):
        """Should get protocol hierarchy statistics."""
        from src.wireshark.core.pcap_analyzer import PcapAnalyzer

        analyzer = PcapAnalyzer()

        pcap_files = list(TEST_PCAP_DIR.glob("**/*.pcap"))
        if not pcap_files:
            pytest.skip("No test pcap files available")

        test_pcap = str(pcap_files[0])
        stats = analyzer.get_protocol_hierarchy(test_pcap)

        assert isinstance(stats, list)

    def test_get_top_talkers(self):
        """Should identify top talking hosts."""
        from src.wireshark.core.pcap_analyzer import PcapAnalyzer

        analyzer = PcapAnalyzer()

        pcap_files = list(TEST_PCAP_DIR.glob("**/*.pcap"))
        if not pcap_files:
            pytest.skip("No test pcap files available")

        test_pcap = str(pcap_files[0])
        talkers = analyzer.get_top_talkers(test_pcap, limit=10)

        assert isinstance(talkers, list)
        assert len(talkers) <= 10
