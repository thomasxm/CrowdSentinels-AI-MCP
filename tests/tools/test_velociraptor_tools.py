"""Tests for VelociraptorTools MCP tool class."""

import os
from unittest.mock import MagicMock, patch

import pytest


class TestVelociraptorToolsInit:
    """Test VelociraptorTools initialization and configuration."""

    def test_init_without_config_raises(self):
        """Should raise when VELOCIRAPTOR_API_CONFIG is not set."""
        from src.tools.velociraptor_tools import VelociraptorTools

        tools = VelociraptorTools()

        with patch.dict(os.environ, {}, clear=True), pytest.raises(RuntimeError, match="VELOCIRAPTOR_API_CONFIG"):
            tools._get_client()

    def test_init_with_config_creates_client(self):
        """Should create VelociraptorClient when config path is set."""
        from src.tools.velociraptor_tools import VelociraptorTools

        tools = VelociraptorTools()

        with (
            patch.dict(os.environ, {"VELOCIRAPTOR_API_CONFIG": "/tmp/test_api.yaml"}),
            patch("src.clients.velociraptor_client.VelociraptorClient") as mock_client,
        ):
            tools._get_client()
            mock_client.assert_called_once_with("/tmp/test_api.yaml")

    def test_lazy_init_caches_client(self):
        """Should reuse client on subsequent calls."""
        from src.tools.velociraptor_tools import VelociraptorTools

        tools = VelociraptorTools()

        with (
            patch.dict(os.environ, {"VELOCIRAPTOR_API_CONFIG": "/tmp/test_api.yaml"}),
            patch("src.clients.velociraptor_client.VelociraptorClient") as mock_client,
        ):
            tools._get_client()
            tools._get_client()
            # Only one instantiation
            assert mock_client.call_count == 1


class TestVelociraptorToolsRegistration:
    """Test that tools register correctly with FastMCP."""

    def test_register_tools_creates_expected_tools(self):
        """All expected Velociraptor tools should be registered."""
        from src.tools.velociraptor_tools import VelociraptorTools

        tools = VelociraptorTools()
        mcp = MagicMock()

        # Track decorated functions
        registered = []

        def mock_tool():
            def decorator(func):
                registered.append(func.__name__)
                return func
            return decorator

        mcp.tool = mock_tool
        tools.register_tools(mcp)

        expected_tools = [
            "velociraptor_client_info",
            "velociraptor_pslist",
            "velociraptor_netstat",
            "velociraptor_users",
            "velociraptor_groups",
            "velociraptor_mounts",
            "velociraptor_scheduled_tasks",
            "velociraptor_services",
            "velociraptor_prefetch",
            "velociraptor_shimcache",
            "velociraptor_amcache",
            "velociraptor_userassist",
            "velociraptor_bam",
            "velociraptor_shellbags",
            "velociraptor_recentdocs",
            "velociraptor_evidence_of_download",
            "velociraptor_ntfs_mft",
            "velociraptor_collect_artifact",
            "velociraptor_get_collection_results",
            "velociraptor_list_artifacts",
        ]

        for tool_name in expected_tools:
            assert tool_name in registered, f"Missing tool: {tool_name}"


class TestWrapResults:
    """Test result wrapping and auto-capture integration."""

    def test_wrap_results_structure(self):
        """Wrapped results should have standard structure."""
        from src.tools.velociraptor_tools import VelociraptorTools

        tools = VelociraptorTools()
        raw = [{"Name": "test.exe", "Pid": 123}]

        with patch("src.tools.velociraptor_tools.auto_capture_velociraptor_results") as mock_capture:
            mock_capture.side_effect = lambda results, *args, **kwargs: results
            result = tools._wrap_results(raw, "test_tool", "test description")

        assert result["events"] == raw
        assert result["total_hits"] == 1
        assert result["source"] == "velociraptor"

    def test_wrap_results_calls_auto_capture(self):
        """Wrapping should invoke auto-capture for investigation state."""
        from src.tools.velociraptor_tools import VelociraptorTools

        tools = VelociraptorTools()
        raw = [{"Name": "suspicious.exe"}]

        with patch("src.tools.velociraptor_tools.auto_capture_velociraptor_results") as mock_capture:
            mock_capture.return_value = {"events": raw, "capture_info": {"captured": True}}
            result = tools._wrap_results(raw, "velociraptor_pslist", "Process list")

        mock_capture.assert_called_once()
        call_args = mock_capture.call_args
        assert call_args[0][1] == "velociraptor_pslist"
        assert call_args[0][2] == "Process list"
