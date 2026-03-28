"""System tests: graceful degradation via MCP.

Verifies tools return clean error messages (not crashes or stack traces)
when providers are unavailable or inputs are invalid.
"""

import pytest
from fastmcp import Client


@pytest.mark.asyncio
async def test_search_misp_not_configured(mcp_server):
    """search_misp returns clean error when MISP not configured."""
    async with Client(mcp_server) as client:
        result = await client.call_tool(
            "search_misp",
            {"ioc_value": "8.8.8.8"},
        )
        text = str(result)
        # Should say "not configured", not crash with a traceback
        assert "not configured" in text.lower() or "MISP_URL" in text
        assert "Traceback" not in text


@pytest.mark.asyncio
async def test_lookup_invalid_ioc_type(mcp_server):
    """lookup_ioc with invalid type returns clean error."""
    async with Client(mcp_server) as client:
        result = await client.call_tool(
            "lookup_ioc",
            {"ioc_type": "banana", "ioc_value": "fruit"},
        )
        text = str(result)
        assert "unsupported" in text.lower() or "error" in text.lower()
        assert "Traceback" not in text


@pytest.mark.asyncio
async def test_lookup_unsupported_type_no_crash(mcp_server):
    """lookup_ioc with a type that has no providers returns unknown, not crash."""
    async with Client(mcp_server) as client:
        result = await client.call_tool(
            "lookup_ioc",
            {"ioc_type": "user", "ioc_value": "admin"},
        )
        text = str(result)
        assert "unknown" in text.lower() or "no providers" in text.lower()
        assert "Traceback" not in text


@pytest.mark.asyncio
async def test_enrich_without_investigation(mcp_server):
    """enrich_iocs returns clean error when no investigation exists."""
    # Reset the investigation state client so no active investigation
    import src.storage.auto_capture as ac

    old_client = ac._client
    ac._client = None  # Force fresh client with no investigation

    try:
        async with Client(mcp_server) as client:
            result = await client.call_tool("enrich_iocs", {})
            text = str(result)
            assert "error" in text.lower() or "no investigation" in text.lower()
            assert "Traceback" not in text
    finally:
        ac._client = old_client


@pytest.mark.asyncio
@pytest.mark.expects_tool_failure
async def test_search_nonexistent_index(mcp_server):
    """search_documents on nonexistent index returns error, not crash."""
    async with Client(mcp_server) as client:
        result = await client.call_tool(
            "search_documents",
            {"index": "nonexistent-index-xyz-999", "body": {"query": {"match_all": {}}, "size": 1}},
        )
        text = str(result)
        # Should be an error message, not a Python traceback
        assert "error" in text.lower() or "not_found" in text.lower() or "index_not_found" in text.lower()
        assert "Traceback" not in text


@pytest.mark.asyncio
@pytest.mark.expects_tool_failure
async def test_export_iocs_unknown_format(mcp_server):
    """export_iocs with unknown format returns clean error."""
    async with Client(mcp_server) as client:
        # Need an investigation first
        await client.call_tool(
            "create_investigation",
            {"name": "Degradation Test: Unknown Format"},
        )

        result = await client.call_tool(
            "export_iocs",
            {"format": "pdf"},
        )
        text = str(result)
        assert "unknown format" in text.lower() or "error" in text.lower()
        assert "Traceback" not in text

        await client.call_tool("close_investigation", {"resolution": "test"})
