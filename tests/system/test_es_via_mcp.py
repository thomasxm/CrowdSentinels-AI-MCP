"""System tests: real Elasticsearch queries via MCP protocol.

Every call goes through: FastMCP Client -> MCP JSON-RPC -> handle_search_exceptions
-> ES client -> real Elasticsearch -> response -> serialisation -> Client.
"""

import pytest
from fastmcp import Client


@pytest.mark.asyncio
async def test_cluster_health(mcp_server):
    """cluster_health returns real ES status via MCP."""
    async with Client(mcp_server) as client:
        result = await client.call_tool("get_cluster_health", {})
        text = str(result)
        assert any(s in text for s in ["green", "yellow", "red"]), f"Unexpected health response: {text[:200]}"


@pytest.mark.asyncio
async def test_list_indices(mcp_server):
    """list_indices returns real indices from ES."""
    async with Client(mcp_server) as client:
        result = await client.call_tool("list_indices", {})
        text = str(result)
        assert "winlogbeat" in text or "cef-ssh" in text, f"Expected known indices, got: {text[:300]}"


@pytest.mark.asyncio
async def test_search_documents_ssh(mcp_server):
    """search_documents returns real SSH brute force events."""
    async with Client(mcp_server) as client:
        result = await client.call_tool(
            "search_documents",
            {
                "index": "cef-ssh-*",
                "body": {"query": {"match": {"name": "login attempt"}}, "size": 3},
            },
        )
        text = str(result)
        assert "login attempt" in text.lower() or "sourceAddress" in text, f"Expected SSH events, got: {text[:300]}"


@pytest.mark.asyncio
async def test_search_documents_winlogbeat(mcp_server):
    """search_documents returns real Windows event log data."""
    async with Client(mcp_server) as client:
        result = await client.call_tool(
            "search_documents",
            {
                "index": ".ds-winlogbeat-*",
                "body": {"query": {"match_all": {}}, "size": 2},
            },
        )
        text = str(result)
        assert "host" in text or "event" in text or "winlog" in text, f"Expected winlogbeat events, got: {text[:300]}"


@pytest.mark.asyncio
async def test_get_index(mcp_server):
    """get_index returns real index info (mappings, settings, aliases)."""
    async with Client(mcp_server) as client:
        result = await client.call_tool(
            "get_index",
            {"index": "cef-ssh-2016.11.15"},
        )
        text = str(result)
        assert "sourceAddress" in text or "mappings" in text or "properties" in text, (
            f"Expected index info, got: {text[:300]}"
        )
