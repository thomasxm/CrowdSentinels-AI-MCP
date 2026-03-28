"""MCP tools for index listing, mapping, and settings."""

from fastmcp import FastMCP


class IndexTools:
    def __init__(self, search_client):
        self.search_client = search_client

    def register_tools(self, mcp: FastMCP):
        @mcp.tool()
        def list_indices() -> list[dict]:
            """List all indices."""
            return self.search_client.list_indices()

        @mcp.tool()
        def get_index(index: str) -> dict:
            """
            Returns information (mappings, settings, aliases) about one or more indices.

            Args:
                index: Name of the index
            """
            return self.search_client.get_index(index=index)

        @mcp.tool()
        def create_index(index: str, body: dict | None = None) -> dict:
            """
            Create a new index.

            Args:
                index: Name of the index
                body: Optional index configuration including mappings and settings
            """
            return self.search_client.create_index(index=index, body=body)

        @mcp.tool()
        def delete_index(index: str) -> dict:
            """
            Delete an index.

            Args:
                index: Name of the index
            """
            return self.search_client.delete_index(index=index)
