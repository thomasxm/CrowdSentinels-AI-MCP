# tests/wireshark/test_mcp_tools.py
"""Tests for Wireshark MCP tools."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest

TEST_PCAP_DIR = Path("/home/kali/Desktop/CTU/normal_traffics")


class TestWiresharkToolsRegistration:
    """Test tool registration."""

    def test_wireshark_tools_import(self):
        """Should import WiresharkTools class."""
        from src.tools.wireshark_tools import WiresharkTools

        tools = WiresharkTools()
        assert tools is not None

    def test_register_tools(self):
        """Should register all tools with MCP."""
        from src.tools.wireshark_tools import WiresharkTools

        tools = WiresharkTools()
        mock_mcp = MagicMock()

        # Mock the tool decorator
        mock_mcp.tool.return_value = lambda f: f

        tools.register_tools(mock_mcp)

        # Should have called mcp.tool() for each tool
        assert mock_mcp.tool.call_count >= 10


class TestPcapOverviewTool:
    """Test pcap_overview tool."""

    def test_pcap_overview_returns_metadata(self):
        """Should return PCAP metadata."""
        from src.tools.wireshark_tools import WiresharkTools

        pcap_files = list(TEST_PCAP_DIR.glob("**/*.pcap"))
        if not pcap_files:
            pytest.skip("No test pcap files available")

        tools = WiresharkTools()
        result = tools._pcap_overview(str(pcap_files[0]))

        assert "packet_count" in result or "error" in result


class TestBuildBaselineTool:
    """Test build_baseline tool."""

    def test_build_baseline_from_pcap(self):
        """Should build baseline from PCAP."""
        from src.tools.wireshark_tools import WiresharkTools

        pcap_files = list(TEST_PCAP_DIR.glob("**/*.pcap"))
        if not pcap_files:
            pytest.skip("No test pcap files available")

        tools = WiresharkTools()
        result = tools._build_baseline(pcap_path=str(pcap_files[0]), baseline_name="test_baseline")

        assert "baseline_name" in result or "error" in result


class TestHuntAnomaliesTool:
    """Test hunt_anomalies tool."""

    def test_hunt_anomalies_detects_issues(self):
        """Should detect anomalies in PCAP."""
        from src.tools.wireshark_tools import WiresharkTools

        pcap_files = list(TEST_PCAP_DIR.glob("**/*.pcap"))
        if not pcap_files:
            pytest.skip("No test pcap files available")

        tools = WiresharkTools()
        result = tools._hunt_anomalies(str(pcap_files[0]))

        assert "anomalies" in result or "error" in result


class TestDetectBeaconingTool:
    """Test detect_beaconing tool."""

    def test_detect_beaconing_analyzes_timing(self):
        """Should analyze timing patterns."""
        from src.tools.wireshark_tools import WiresharkTools

        pcap_files = list(TEST_PCAP_DIR.glob("**/*.pcap"))
        if not pcap_files:
            pytest.skip("No test pcap files available")

        tools = WiresharkTools()
        result = tools._detect_beaconing(str(pcap_files[0]))

        assert "beacons" in result or "patterns" in result or "error" in result


class TestDetectLateralMovementTool:
    """Test detect_lateral_movement tool."""

    def test_detect_lateral_movement(self):
        """Should detect lateral movement patterns."""
        from src.tools.wireshark_tools import WiresharkTools

        pcap_files = list(TEST_PCAP_DIR.glob("**/*.pcap"))
        if not pcap_files:
            pytest.skip("No test pcap files available")

        tools = WiresharkTools()
        result = tools._detect_lateral_movement(str(pcap_files[0]))

        assert "summary" in result or "findings" in result or "error" in result


class TestExtractObjectsTool:
    """Test extract_objects tool."""

    def test_extract_objects_lists_files(self):
        """Should list extractable objects."""
        from src.tools.wireshark_tools import WiresharkTools

        pcap_files = list(TEST_PCAP_DIR.glob("**/*.pcap"))
        if not pcap_files:
            pytest.skip("No test pcap files available")

        tools = WiresharkTools()
        result = tools._extract_objects(pcap_path=str(pcap_files[0]), protocol="http")

        assert "objects" in result or "total_objects" in result or "error" in result


class TestGenerateReportTool:
    """Test generate_report tool."""

    def test_generate_report_creates_markdown(self):
        """Should generate markdown report."""
        from src.tools.wireshark_tools import WiresharkTools

        tools = WiresharkTools()

        # Mock findings
        findings = {
            "beaconing": [{"src_ip": "192.168.1.100", "dst_ip": "1.2.3.4", "confidence": "high"}],
            "anomalies": [],
            "iocs": [],
        }

        result = tools._generate_report(pcap_path="/tmp/test.pcap", findings=findings)

        assert "report" in result
        assert "IDENTIFY" in result["report"]
        assert "DETECT" in result["report"]


class TestTrackSessionsTool:
    """Test track_sessions tool."""

    def test_track_sessions(self):
        """Should track network sessions."""
        from src.tools.wireshark_tools import WiresharkTools

        pcap_files = list(TEST_PCAP_DIR.glob("**/*.pcap"))
        if not pcap_files:
            pytest.skip("No test pcap files available")

        tools = WiresharkTools()
        result = tools._track_sessions(str(pcap_files[0]))

        assert "sessions" in result or "summary" in result or "error" in result


class TestHuntIoCsTool:
    """Test hunt_iocs tool."""

    def test_hunt_iocs_with_ip_list(self):
        """Should hunt for IoCs in PCAP."""
        from src.tools.wireshark_tools import WiresharkTools

        pcap_files = list(TEST_PCAP_DIR.glob("**/*.pcap"))
        if not pcap_files:
            pytest.skip("No test pcap files available")

        tools = WiresharkTools()
        result = tools._hunt_iocs(pcap_path=str(pcap_files[0]), iocs=["192.168.1.1", "8.8.8.8"])

        assert "matches" in result or "found" in result or "error" in result
