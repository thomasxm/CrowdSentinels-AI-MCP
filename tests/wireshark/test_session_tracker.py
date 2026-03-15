# tests/wireshark/test_session_tracker.py
"""Tests for session tracker."""
from pathlib import Path

import pytest

TEST_PCAP_DIR = Path("/home/kali/Desktop/CTU/normal_traffics")


class TestSessionTracker:
    """Test TCP/UDP session reconstruction."""

    def test_build_session_from_packets(self):
        """Should build session from packet list."""
        from src.wireshark.hunting.session_tracker import SessionTracker

        tracker = SessionTracker()

        # Simulated TCP packets for a single stream
        packets = [
            {
                "tcp.stream": "1",
                "ip.src": "192.168.1.100",
                "ip.dst": "203.0.113.42",
                "tcp.srcport": "52345",
                "tcp.dstport": "443",
                "frame.time_epoch": "1704067200.0",
                "frame.len": "60",
                "tcp.flags": "0x002"  # SYN
            },
            {
                "tcp.stream": "1",
                "ip.src": "203.0.113.42",
                "ip.dst": "192.168.1.100",
                "tcp.srcport": "443",
                "tcp.dstport": "52345",
                "frame.time_epoch": "1704067200.1",
                "frame.len": "60",
                "tcp.flags": "0x012"  # SYN-ACK
            },
            {
                "tcp.stream": "1",
                "ip.src": "192.168.1.100",
                "ip.dst": "203.0.113.42",
                "tcp.srcport": "52345",
                "tcp.dstport": "443",
                "frame.time_epoch": "1704067200.2",
                "frame.len": "52",
                "tcp.flags": "0x010"  # ACK
            },
        ]

        sessions = tracker.build_sessions_from_packets(packets)

        assert len(sessions) == 1
        session = sessions[0]
        assert session.stream_id == 1
        assert session.protocol == "tcp"
        assert session.src_ip == "192.168.1.100"
        assert session.dst_ip == "203.0.113.42"
        assert session.dst_port == 443
        assert session.packet_count == 3

    def test_identify_initiator(self):
        """Should correctly identify session initiator (client)."""
        from src.wireshark.hunting.session_tracker import SessionTracker

        tracker = SessionTracker()

        packets = [
            # First packet with SYN from client
            {
                "tcp.stream": "1",
                "ip.src": "192.168.1.100",
                "ip.dst": "8.8.8.8",
                "tcp.srcport": "12345",
                "tcp.dstport": "53",
                "frame.time_epoch": "1704067200.0",
                "frame.len": "60",
                "tcp.flags": "0x002"  # SYN
            },
        ]

        sessions = tracker.build_sessions_from_packets(packets)

        assert len(sessions) == 1
        # Client should be src_ip (the one who initiated)
        assert sessions[0].src_ip == "192.168.1.100"

    def test_calculate_byte_count(self):
        """Should calculate total bytes in session."""
        from src.wireshark.hunting.session_tracker import SessionTracker

        tracker = SessionTracker()

        packets = [
            {"tcp.stream": "1", "ip.src": "192.168.1.100", "ip.dst": "8.8.8.8",
             "tcp.srcport": "12345", "tcp.dstport": "80",
             "frame.time_epoch": "1704067200.0", "frame.len": "100", "tcp.flags": "0x010"},
            {"tcp.stream": "1", "ip.src": "8.8.8.8", "ip.dst": "192.168.1.100",
             "tcp.srcport": "80", "tcp.dstport": "12345",
             "frame.time_epoch": "1704067200.1", "frame.len": "1500", "tcp.flags": "0x010"},
        ]

        sessions = tracker.build_sessions_from_packets(packets)

        assert sessions[0].byte_count == 1600

    def test_extract_tcp_flags(self):
        """Should extract TCP flags from session."""
        from src.wireshark.hunting.session_tracker import SessionTracker

        tracker = SessionTracker()

        packets = [
            {"tcp.stream": "1", "ip.src": "192.168.1.100", "ip.dst": "8.8.8.8",
             "tcp.srcport": "12345", "tcp.dstport": "80",
             "frame.time_epoch": "1704067200.0", "frame.len": "60", "tcp.flags": "0x002"},  # SYN
            {"tcp.stream": "1", "ip.src": "8.8.8.8", "ip.dst": "192.168.1.100",
             "tcp.srcport": "80", "tcp.dstport": "12345",
             "frame.time_epoch": "1704067200.1", "frame.len": "60", "tcp.flags": "0x012"},  # SYN-ACK
            {"tcp.stream": "1", "ip.src": "192.168.1.100", "ip.dst": "8.8.8.8",
             "tcp.srcport": "12345", "tcp.dstport": "80",
             "frame.time_epoch": "1704067200.2", "frame.len": "52", "tcp.flags": "0x010"},  # ACK
        ]

        sessions = tracker.build_sessions_from_packets(packets)

        assert "SYN" in sessions[0].flags
        assert "ACK" in sessions[0].flags

    def test_multiple_sessions(self):
        """Should handle multiple concurrent sessions."""
        from src.wireshark.hunting.session_tracker import SessionTracker

        tracker = SessionTracker()

        packets = [
            # Session 1
            {"tcp.stream": "1", "ip.src": "192.168.1.100", "ip.dst": "8.8.8.8",
             "tcp.srcport": "12345", "tcp.dstport": "443",
             "frame.time_epoch": "1704067200.0", "frame.len": "60", "tcp.flags": "0x002"},
            # Session 2
            {"tcp.stream": "2", "ip.src": "192.168.1.101", "ip.dst": "1.1.1.1",
             "tcp.srcport": "54321", "tcp.dstport": "80",
             "frame.time_epoch": "1704067200.1", "frame.len": "60", "tcp.flags": "0x002"},
            # Session 1 continued
            {"tcp.stream": "1", "ip.src": "8.8.8.8", "ip.dst": "192.168.1.100",
             "tcp.srcport": "443", "tcp.dstport": "12345",
             "frame.time_epoch": "1704067200.2", "frame.len": "60", "tcp.flags": "0x012"},
        ]

        sessions = tracker.build_sessions_from_packets(packets)

        assert len(sessions) == 2
        # Find session to 8.8.8.8
        session_1 = next(s for s in sessions if s.dst_ip == "8.8.8.8")
        assert session_1.packet_count == 2

    def test_track_sessions_from_pcap(self):
        """Should track sessions from PCAP file."""
        from src.wireshark.hunting.session_tracker import SessionTracker

        pcap_files = list(TEST_PCAP_DIR.glob("**/*.pcap"))
        if not pcap_files:
            pytest.skip("No test pcap files available")

        tracker = SessionTracker()
        sessions = tracker.track_from_pcap(str(pcap_files[0]))

        assert isinstance(sessions, list)
        # Should have some sessions in normal traffic
        if sessions:
            assert sessions[0].stream_id is not None
            assert sessions[0].protocol in ["tcp", "udp"]

    def test_filter_by_port(self):
        """Should filter sessions by port."""
        from src.wireshark.hunting.session_tracker import SessionTracker

        tracker = SessionTracker()

        packets = [
            {"tcp.stream": "1", "ip.src": "192.168.1.100", "ip.dst": "8.8.8.8",
             "tcp.srcport": "12345", "tcp.dstport": "443",
             "frame.time_epoch": "1704067200.0", "frame.len": "60", "tcp.flags": "0x002"},
            {"tcp.stream": "2", "ip.src": "192.168.1.100", "ip.dst": "8.8.8.8",
             "tcp.srcport": "12346", "tcp.dstport": "80",
             "frame.time_epoch": "1704067200.1", "frame.len": "60", "tcp.flags": "0x002"},
        ]

        sessions = tracker.build_sessions_from_packets(packets)
        filtered = tracker.filter_by_port(sessions, [443])

        assert len(filtered) == 1
        assert filtered[0].dst_port == 443

    def test_filter_by_ip(self):
        """Should filter sessions by IP address."""
        from src.wireshark.hunting.session_tracker import SessionTracker

        tracker = SessionTracker()

        packets = [
            {"tcp.stream": "1", "ip.src": "192.168.1.100", "ip.dst": "8.8.8.8",
             "tcp.srcport": "12345", "tcp.dstport": "443",
             "frame.time_epoch": "1704067200.0", "frame.len": "60", "tcp.flags": "0x002"},
            {"tcp.stream": "2", "ip.src": "192.168.1.100", "ip.dst": "1.1.1.1",
             "tcp.srcport": "12346", "tcp.dstport": "443",
             "frame.time_epoch": "1704067200.1", "frame.len": "60", "tcp.flags": "0x002"},
        ]

        sessions = tracker.build_sessions_from_packets(packets)
        filtered = tracker.filter_by_ip(sessions, ["8.8.8.8"])

        assert len(filtered) == 1
        assert filtered[0].dst_ip == "8.8.8.8"
