# tests/wireshark/test_baseline_builder.py
"""Tests for baseline builder (auto-learn)."""

from pathlib import Path

import pytest

TEST_PCAP_DIR = Path("/home/kali/Desktop/CTU/normal_traffics")


class TestBaselineBuilder:
    """Test auto-learn baseline builder."""

    def test_build_baseline_from_pcap(self):
        """Should build baseline from normal traffic pcap."""
        from src.wireshark.baseline.baseline_builder import BaselineBuilder

        builder = BaselineBuilder()

        pcap_files = list(TEST_PCAP_DIR.glob("**/*.pcap"))
        if not pcap_files:
            pytest.skip("No test pcap files available")

        # Use first small pcap
        test_pcap = str(pcap_files[0])
        baseline = builder.build_from_pcap(test_pcap)

        assert baseline is not None
        assert "observed_ports" in baseline
        assert "observed_ips" in baseline
        assert "observed_protocols" in baseline

    def test_merge_baselines(self):
        """Should merge multiple baselines."""
        from src.wireshark.baseline.baseline_builder import BaselineBuilder

        builder = BaselineBuilder()

        baseline1 = {"observed_ports": {"tcp": [80, 443]}, "observed_ips": ["192.168.1.1"]}
        baseline2 = {"observed_ports": {"tcp": [443, 8080]}, "observed_ips": ["192.168.1.2"]}

        merged = builder.merge_baselines([baseline1, baseline2])

        assert 80 in merged["observed_ports"]["tcp"]
        assert 443 in merged["observed_ports"]["tcp"]
        assert 8080 in merged["observed_ports"]["tcp"]
        assert "192.168.1.1" in merged["observed_ips"]
        assert "192.168.1.2" in merged["observed_ips"]
