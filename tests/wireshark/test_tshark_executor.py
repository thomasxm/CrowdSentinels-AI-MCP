# tests/wireshark/test_tshark_executor.py
"""Tests for TShark command executor."""
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock


class TestTSharkExecutor:
    """Test TShark command execution."""

    def test_check_tshark_available(self):
        """Should detect if tshark is available."""
        from src.wireshark.core.tshark_executor import TSharkExecutor

        executor = TSharkExecutor()

        # tshark should be available on this system
        assert executor.is_available()

    def test_get_version(self):
        """Should get tshark version."""
        from src.wireshark.core.tshark_executor import TSharkExecutor

        executor = TSharkExecutor()
        version = executor.get_version()

        assert version is not None
        assert "TShark" in version or "tshark" in version.lower()

    def test_build_read_command(self):
        """Should build correct command for reading pcap."""
        from src.wireshark.core.tshark_executor import TSharkExecutor

        executor = TSharkExecutor()
        cmd = executor.build_command(
            pcap_path="/tmp/test.pcap",
            display_filter="tcp",
            fields=["ip.src", "ip.dst"]
        )

        assert "-r" in cmd
        assert "/tmp/test.pcap" in cmd
        assert "-Y" in cmd
        assert "tcp" in cmd
        assert "-e" in cmd
        assert "ip.src" in cmd

    def test_build_stats_command(self):
        """Should build correct command for statistics."""
        from src.wireshark.core.tshark_executor import TSharkExecutor

        executor = TSharkExecutor()
        cmd = executor.build_stats_command(
            pcap_path="/tmp/test.pcap",
            stat_type="io,phs"
        )

        assert "-r" in cmd
        assert "-q" in cmd
        assert "-z" in cmd
        assert "io,phs" in cmd


class TestTSharkCommandBuilder:
    """Test command building utilities."""

    def test_escape_filter_value(self):
        """Should properly escape filter values."""
        from src.wireshark.core.tshark_executor import escape_filter_value

        # Normal value
        assert escape_filter_value("192.168.1.1") == "192.168.1.1"

        # Value with quotes
        escaped = escape_filter_value('test"value')
        assert '"' not in escaped or '\\"' in escaped

    def test_build_ip_filter(self):
        """Should build IP address filter."""
        from src.wireshark.core.tshark_executor import build_ip_filter

        filter_str = build_ip_filter(["192.168.1.1", "10.0.0.1"])

        assert "ip.addr" in filter_str
        assert "192.168.1.1" in filter_str
        assert "10.0.0.1" in filter_str
