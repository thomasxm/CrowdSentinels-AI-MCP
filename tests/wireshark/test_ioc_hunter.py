# tests/wireshark/test_ioc_hunter.py
"""Tests for IoC hunter."""
from pathlib import Path

import pytest

TEST_PCAP_DIR = Path("/home/kali/Desktop/CTU/normal_traffics")


class TestIoCHunter:
    """Test IoC-driven traffic filtering."""

    def test_hunt_ip_in_connections(self):
        """Should find connections to/from target IP."""
        from src.wireshark.hunting.ioc_hunter import IoCHunter

        hunter = IoCHunter()

        connections = [
            {"src_ip": "192.168.1.100", "dst_ip": "8.8.8.8", "protocol": "dns"},
            {"src_ip": "192.168.1.100", "dst_ip": "203.0.113.42", "protocol": "tcp"},
            {"src_ip": "10.0.0.1", "dst_ip": "192.168.1.100", "protocol": "tcp"},
        ]

        matches = hunter.hunt_ips(["203.0.113.42"], connections)

        assert len(matches) == 1
        assert matches[0]["dst_ip"] == "203.0.113.42"

    def test_hunt_domain_in_dns(self):
        """Should find DNS queries for target domains."""
        from src.wireshark.hunting.ioc_hunter import IoCHunter

        hunter = IoCHunter()

        dns_queries = [
            {"query_name": "google.com", "src_ip": "192.168.1.100"},
            {"query_name": "evil.com", "src_ip": "192.168.1.100"},
            {"query_name": "subdomain.evil.com", "src_ip": "192.168.1.100"},
        ]

        matches = hunter.hunt_domains(["evil.com"], dns_queries)

        assert len(matches) == 2  # evil.com and subdomain.evil.com
        assert any("evil.com" in m["query_name"] for m in matches)

    def test_hunt_ip_not_found(self):
        """Should return empty list when IP not found."""
        from src.wireshark.hunting.ioc_hunter import IoCHunter

        hunter = IoCHunter()

        connections = [
            {"src_ip": "192.168.1.100", "dst_ip": "8.8.8.8", "protocol": "dns"},
        ]

        matches = hunter.hunt_ips(["203.0.113.42"], connections)

        assert len(matches) == 0

    def test_hunt_multiple_iocs(self):
        """Should find all matching IoCs."""
        from src.wireshark.hunting.ioc_hunter import IoCHunter

        hunter = IoCHunter()

        connections = [
            {"src_ip": "192.168.1.100", "dst_ip": "1.1.1.1", "protocol": "dns"},
            {"src_ip": "192.168.1.100", "dst_ip": "203.0.113.42", "protocol": "tcp"},
            {"src_ip": "10.0.0.5", "dst_ip": "192.168.1.100", "protocol": "tcp"},
        ]

        # Hunt for multiple IPs
        matches = hunter.hunt_ips(["203.0.113.42", "10.0.0.5"], connections)

        assert len(matches) == 2

    def test_hunt_from_pcap(self):
        """Should hunt IoCs in PCAP file."""
        from src.wireshark.hunting.ioc_hunter import IoCHunter

        hunter = IoCHunter()

        pcap_files = list(TEST_PCAP_DIR.glob("**/*.pcap"))
        if not pcap_files:
            pytest.skip("No test pcap files available")

        # Hunt for common DNS servers (should find in normal traffic)
        results = hunter.hunt_iocs_in_pcap(
            pcap_path=str(pcap_files[0]),
            ip_iocs=["8.8.8.8", "1.1.1.1"]  # Common DNS servers
        )

        assert "matches" in results
        assert "summary" in results
