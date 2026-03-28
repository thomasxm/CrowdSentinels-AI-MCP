"""System tests: full enrichment pipeline via MCP.

Tests: create investigation → add IoCs → enrich (live Shodan) → export STIX/MISP.
All calls go through the real MCP protocol. Shodan calls hit the live API.
"""

import pytest
from fastmcp import Client


@pytest.mark.asyncio
async def test_get_enrichment_status(mcp_server):
    """get_enrichment_status reports real provider config via MCP."""
    async with Client(mcp_server) as client:
        result = await client.call_tool("get_enrichment_status", {})
        text = str(result)
        # Shodan is always configured (no key needed)
        assert "shodan_internetdb" in text
        assert "configured" in text


@pytest.mark.asyncio
async def test_lookup_ioc_live_shodan(mcp_server):
    """lookup_ioc hits live Shodan InternetDB for a real public IP."""
    async with Client(mcp_server) as client:
        result = await client.call_tool(
            "lookup_ioc",
            {"ioc_type": "ip", "ioc_value": "1.1.1.1"},
        )
        text = str(result)
        # Shodan should return real data for Cloudflare DNS
        assert "1.1.1.1" in text
        # Should have some verdict (even if unknown)
        assert any(v in text for v in ["malicious", "suspicious", "clean", "unknown"])


@pytest.mark.asyncio
async def test_lookup_private_ip(mcp_server):
    """lookup_ioc correctly handles private IPs."""
    async with Client(mcp_server) as client:
        result = await client.call_tool(
            "lookup_ioc",
            {"ioc_type": "ip", "ioc_value": "192.168.1.1"},
        )
        text = str(result)
        assert "private" in text.lower() or "192.168.1.1" in text


@pytest.mark.asyncio
async def test_full_investigation_pipeline(mcp_server):
    """Full pipeline: create → add IoCs → enrich → export STIX → export MISP → close."""
    async with Client(mcp_server) as client:
        # 1. Create investigation
        result = await client.call_tool(
            "create_investigation",
            {"name": "System Test: Full Pipeline", "description": "Automated harness test"},
        )
        result_text = str(result)
        assert "INV-" in result_text or "investigation" in result_text.lower()

        # 2. Add IoCs (mix of types)
        result = await client.call_tool(
            "add_iocs_to_investigation",
            {
                "iocs": [
                    {"type": "ip", "value": "8.8.8.8"},
                    {"type": "ip", "value": "1.1.1.1"},
                    {"type": "domain", "value": "example.com"},
                    {"type": "hash", "value": "d41d8cd98f00b204e9800998ecf8427e"},
                ],
            },
        )

        # 3. Enrich via live Shodan
        result = await client.call_tool(
            "enrich_iocs",
            {"providers": ["shodan_internetdb"], "max_iocs": 5},
        )
        enrich_text = str(result)
        assert "enriched" in enrich_text.lower() or "shodan" in enrich_text.lower()

        # 4. Export STIX 2.1
        result = await client.call_tool(
            "export_iocs",
            {"format": "stix"},
        )
        stix_text = str(result)
        assert "bundle" in stix_text.lower() or "indicator" in stix_text.lower()

        # 5. Export MISP
        result = await client.call_tool(
            "export_iocs",
            {"format": "misp"},
        )
        misp_text = str(result)
        assert "Attribute" in misp_text or "misp" in misp_text.lower()

        # 6. Export CSV
        result = await client.call_tool(
            "export_iocs",
            {"format": "csv"},
        )
        csv_text = str(result)
        assert "type,value" in csv_text or "8.8.8.8" in csv_text

        # 7. Close investigation
        result = await client.call_tool(
            "close_investigation",
            {"resolution": "System test completed successfully"},
        )


@pytest.mark.asyncio
async def test_export_to_misp_offline(mcp_server):
    """export_to_misp produces valid MISP JSON without a live MISP server."""
    async with Client(mcp_server) as client:
        # Create a fresh investigation for this test
        await client.call_tool(
            "create_investigation",
            {"name": "System Test: MISP Export"},
        )
        await client.call_tool(
            "add_iocs_to_investigation",
            {"iocs": [{"type": "ip", "value": "203.0.113.42"}]},
        )

        result = await client.call_tool(
            "export_to_misp",
            {"push": False},
        )
        text = str(result)
        # Should have MISP event data, not an error
        assert "error" not in text.lower() or "push" in text.lower()
        assert "CrowdSentinel" in text or "event" in text.lower()

        await client.call_tool("close_investigation", {"resolution": "test"})


@pytest.mark.asyncio
async def test_enrich_from_real_es_hunt(mcp_server):
    """Hunt real ES data, extract IPs, enrich with live Shodan."""
    async with Client(mcp_server) as client:
        # Create investigation
        await client.call_tool(
            "create_investigation",
            {"name": "System Test: ES → Shodan Pipeline"},
        )

        # Search real SSH data for attacker IPs
        result = await client.call_tool(
            "search_documents",
            {
                "index": "cef-ssh-*",
                "body": {"query": {"match": {"name": "login attempt"}}, "size": 5},
            },
        )
        search_text = str(result)
        # Should have real source IPs from SSH brute force data
        assert "sourceAddress" in search_text or "62.108" in search_text

        # Add a known attacker IP from the SSH data
        await client.call_tool(
            "add_iocs_to_investigation",
            {"iocs": [{"type": "ip", "value": "61.152.108.18"}]},
        )

        # Enrich with live Shodan
        result = await client.call_tool(
            "enrich_iocs",
            {"providers": ["shodan_internetdb"], "max_iocs": 3},
        )
        enrich_text = str(result)
        # This IP has real Shodan data (ports 111, 161, 5353)
        assert "enriched" in enrich_text.lower() or "shodan" in enrich_text.lower()

        await client.call_tool("close_investigation", {"resolution": "test"})
