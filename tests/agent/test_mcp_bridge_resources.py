"""Tests for MCPBridge resource support.

Verifies that the bridge can discover and read resources from
the in-process CrowdSentinel MCP server.
"""

import json
from unittest.mock import MagicMock

from src.agent.mcp_bridge import MCPBridge


def _make_mock_server_with_resources(resource_map: dict[str, str]) -> MagicMock:
    """Create a mock SearchMCPServer with resources.

    Args:
        resource_map: Dict of URI -> content to register as resources.
    """
    server = MagicMock()
    mcp = MagicMock()

    # Mock get_tools (async, returns empty dict)
    async def mock_get_tools():
        return {}

    mcp.get_tools = mock_get_tools

    # Mock get_resources (async, returns dict of URI -> Resource)
    mock_resources = {}
    for uri, content in resource_map.items():
        resource_obj = MagicMock()
        resource_obj.description = f"Mock resource: {uri}"
        mock_resources[uri] = resource_obj

    async def mock_get_resources():
        return mock_resources

    mcp.get_resources = mock_get_resources

    # Mock _resource_manager.read_resource (async, returns content)
    async def mock_read_resource(uri):
        if uri in resource_map:
            return resource_map[uri]
        raise ValueError(f"Unknown resource: {uri}")

    mcp._resource_manager = MagicMock()
    mcp._resource_manager.read_resource = mock_read_resource

    server.mcp = mcp
    return server


class TestMCPBridgeResourceDiscovery:
    """Test resource discovery from in-process server."""

    def test_discovers_resources_on_start(self):
        """Bridge should discover resources during start()."""
        server = _make_mock_server_with_resources({
            "crowdsentinel://data-sources": "# Data Sources\n...",
            "crowdsentinel://ioc-reference": "# IoC Reference\n...",
        })

        bridge = MCPBridge(server, [])
        bridge.start()

        resources = bridge.list_resources()
        uris = {r["uri"] for r in resources}
        assert "crowdsentinel://data-sources" in uris
        assert "crowdsentinel://ioc-reference" in uris

    def test_list_resources_returns_metadata(self):
        """list_resources should return URI, server name, and description."""
        server = _make_mock_server_with_resources({
            "crowdsentinel://test-resource": "test content",
        })

        bridge = MCPBridge(server, [])
        bridge.start()

        resources = bridge.list_resources()
        assert len(resources) == 1
        assert resources[0]["uri"] == "crowdsentinel://test-resource"
        assert resources[0]["server"] == "crowdsentinel"
        assert "Mock resource" in resources[0]["description"]

    def test_list_resources_empty_when_none_registered(self):
        """Should return empty list when no resources exist."""
        server = _make_mock_server_with_resources({})

        bridge = MCPBridge(server, [])
        bridge.start()

        assert bridge.list_resources() == []


class TestMCPBridgeResourceReading:
    """Test reading resources from in-process server."""

    def test_read_resource_returns_content(self):
        """Should return the resource content as string."""
        content = "# IoC Reference\nPriority 6: TTPs"
        server = _make_mock_server_with_resources({
            "crowdsentinel://ioc-reference": content,
        })

        bridge = MCPBridge(server, [])
        bridge.start()

        result = bridge.read_resource("crowdsentinel://ioc-reference")
        assert result == content

    def test_read_unknown_resource_returns_error(self):
        """Should return JSON error for unknown URI."""
        server = _make_mock_server_with_resources({})

        bridge = MCPBridge(server, [])
        bridge.start()

        result = bridge.read_resource("crowdsentinel://nonexistent")
        parsed = json.loads(result)
        assert "error" in parsed

    def test_read_resource_caches_result(self):
        """Second read should use cache, not call server again."""
        server = _make_mock_server_with_resources({
            "crowdsentinel://test": "cached content",
        })

        bridge = MCPBridge(server, [])
        bridge.start()

        result1 = bridge.read_resource("crowdsentinel://test")
        result2 = bridge.read_resource("crowdsentinel://test")
        assert result1 == result2 == "cached content"

    def test_read_resource_handles_dict_content(self):
        """Should JSON-serialize dict content."""
        server = _make_mock_server_with_resources({})
        bridge = MCPBridge(server, [])
        bridge.start()

        # Manually populate registry and mock a dict return
        mock_resource = MagicMock()
        bridge._resource_registry["crowdsentinel://data"] = ("crowdsentinel", mock_resource)

        async def mock_read(uri):
            return {"key": "value", "nested": {"a": 1}}

        server.mcp._resource_manager.read_resource = mock_read

        result = bridge.read_resource("crowdsentinel://data")
        parsed = json.loads(result)
        assert parsed["key"] == "value"


class TestMCPBridgeResourceWithTools:
    """Test that resources and tools coexist correctly."""

    def test_start_loads_both_tools_and_resources(self):
        """start() should load both tools and resources."""
        server = MagicMock()
        mcp = MagicMock()

        # Mock tools
        mock_tool = MagicMock()
        mock_mcp_tool = MagicMock()
        mock_mcp_tool.name = "test_tool"
        mock_mcp_tool.description = "A test tool"
        mock_mcp_tool.inputSchema = {}
        mock_tool.to_mcp_tool.return_value = mock_mcp_tool

        async def mock_get_tools():
            return {"test_tool": mock_tool}

        # Mock resources
        mock_resource = MagicMock()
        mock_resource.description = "A test resource"

        async def mock_get_resources():
            return {"crowdsentinel://test": mock_resource}

        mcp.get_tools = mock_get_tools
        mcp.get_resources = mock_get_resources
        server.mcp = mcp

        bridge = MCPBridge(server, [])
        bridge.start()

        assert len(bridge.list_tools()) == 1
        assert len(bridge.list_resources()) == 1
        assert bridge.list_tools()[0]["name"] == "test_tool"
        assert bridge.list_resources()[0]["uri"] == "crowdsentinel://test"


class TestBuildSystemPromptWithResources:
    """Test that resource content is properly injected into system prompt."""

    def test_prompt_without_resources(self):
        """System prompt should work without resources (backward compatible)."""
        from src.agent.prompts import build_system_prompt

        result = build_system_prompt({"crowdsentinel": ["tool1", "tool2"]})
        assert "tool1" in result
        assert "tool2" in result
        assert "Investigation Reference Knowledge" not in result

    def test_prompt_with_resources(self):
        """System prompt should include resource content when provided."""
        from src.agent.prompts import build_system_prompt

        resources = {
            "crowdsentinel://ioc-reference": "# IoC Reference\nPriority 6: CommandLine (TTPs)",
            "crowdsentinel://data-sources": "# Data Sources\nElasticsearch, Velociraptor",
        }

        result = build_system_prompt({"crowdsentinel": ["tool1"]}, resources)
        assert "Investigation Reference Knowledge" in result
        assert "IoC Reference" in result
        assert "Priority 6: CommandLine (TTPs)" in result
        assert "Data Sources" in result

    def test_prompt_truncates_large_resources(self):
        """Resources over 8000 chars should be truncated."""
        from src.agent.prompts import build_system_prompt

        large_content = "x" * 10000
        resources = {"crowdsentinel://big": large_content}

        result = build_system_prompt({"crowdsentinel": ["tool1"]}, resources)
        assert "truncated" in result
        # Should not contain the full 10000 chars
        assert len(result) < len(large_content) + 2000
