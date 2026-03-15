"""MCP tools for index alias management."""

from fastmcp import FastMCP


class AliasTools:
    def __init__(self, search_client):
        self.search_client = search_client
    def register_tools(self, mcp: FastMCP):
        @mcp.tool()
        def list_aliases() -> list[dict]:
            """List all aliases."""
            return self.search_client.list_aliases()

        @mcp.tool()
        def get_alias(index: str) -> dict:
            """
            Get alias information for a specific index.

            Args:
                index: Name of the index
            """
            return self.search_client.get_alias(index=index)

        @mcp.tool()
        def put_alias(index: str, name: str, body: dict) -> dict:
            """
            Create or update an alias for a specific index.

            Args:
                index: Name of the index
                name: Name of the alias
                body: Alias configuration
            """
            return self.search_client.put_alias(index=index, name=name, body=body)

        @mcp.tool()
        def delete_alias(index: str, name: str) -> dict:
            """
            Delete an alias for a specific index.

            Args:
                index: Name of the index
                name: Name of the alias
            """
            return self.search_client.delete_alias(index=index, name=name)

