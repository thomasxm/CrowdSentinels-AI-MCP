"""MCP tools for cluster health and statistics."""

from fastmcp import FastMCP


class ClusterTools:
    def __init__(self, search_client):
        self.search_client = search_client

    def register_tools(self, mcp: FastMCP):
        @mcp.tool()
        def get_cluster_health() -> dict:
            """Returns basic information about the health of the cluster."""
            return self.search_client.get_cluster_health()

        @mcp.tool()
        def get_cluster_stats() -> dict:
            """Returns high-level overview of cluster statistics."""
            return self.search_client.get_cluster_stats()
