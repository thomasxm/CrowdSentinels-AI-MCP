"""System tests: tool registration and MCP protocol basics.

Verifies all expected tools register and respond via the real MCP protocol.
"""

import pytest
from fastmcp import Client

# Tools that MUST be registered (subset — not exhaustive)
CRITICAL_TOOLS = {
    # Core ES
    "get_cluster_health",
    "search_documents",
    "list_indices",
    "get_index",
    # Threat hunting
    "smart_search",
    "threat_hunt_search",
    "hunt_by_timeframe",
    "hunt_for_ioc",
    # Detection rules
    "list_detection_rules",
    "execute_detection_rule",
    # Kill chain
    "analyze_kill_chain_stage",
    # Investigation
    "create_investigation",
    "get_shared_iocs",
    "export_iocs",
    "add_iocs_to_investigation",
    "close_investigation",
    # Threat intelligence
    "enrich_iocs",
    "lookup_ioc",
    "get_enrichment_status",
    "export_to_misp",
    "search_misp",
    # Wireshark
    "pcap_overview",
    "detect_beaconing",
    "detect_lateral_movement",
    "hunt_anomalies",
    "generate_iocs",
    # Chainsaw
    "hunt_with_sigma_rules",
    # Workflow
    "get_investigation_workflow",
}


@pytest.mark.asyncio
async def test_mcp_ping(mcp_server):
    """Server responds to MCP ping."""
    async with Client(mcp_server) as client:
        await client.ping()


@pytest.mark.asyncio
async def test_tool_count_minimum(mcp_server):
    """Server registers at least 84 tools."""
    async with Client(mcp_server) as client:
        tools = await client.list_tools()
        assert len(tools) >= 84, f"Expected >= 84 tools, got {len(tools)}"


@pytest.mark.asyncio
async def test_critical_tools_registered(mcp_server):
    """Every critical tool is registered and accessible via MCP."""
    async with Client(mcp_server) as client:
        tools = await client.list_tools()
        registered = {t.name for t in tools}

        missing = CRITICAL_TOOLS - registered
        assert not missing, f"Critical tools missing from MCP server: {missing}"


@pytest.mark.asyncio
async def test_tools_have_descriptions(mcp_server):
    """Every registered tool has a non-empty description."""
    async with Client(mcp_server) as client:
        tools = await client.list_tools()
        empty = [t.name for t in tools if not t.description or len(t.description.strip()) < 10]
        assert not empty, f"Tools with missing/short descriptions: {empty}"
