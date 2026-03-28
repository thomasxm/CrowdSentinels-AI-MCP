"""Asset Discovery Tools for MCP."""

from fastmcp import FastMCP


class AssetDiscoveryTools:
    def __init__(self, search_client):
        self.search_client = search_client

    def register_tools(self, mcp: FastMCP):
        @mcp.tool()
        def discover_all_assets() -> dict:
            """
            Discover all assets in the Elasticsearch cluster including indices,
            data streams, and their metadata. This will scan all indices and
            extract metadata like OS type, log source, field mappings, etc.

            The discovered assets are saved to assets/discovered_assets.json
            and can be used for incident response and threat hunting.

            Returns:
                Dictionary containing all discovered assets with metadata
            """
            return self.search_client.discover_all_assets()

        @mcp.tool()
        def get_saved_assets() -> dict:
            """
            Retrieve previously discovered assets from the saved file.

            Returns:
                Dictionary containing saved asset information or empty if not found
            """
            assets = self.search_client.get_saved_assets()
            if assets is None:
                return {"message": "No saved assets found. Run discover_all_assets first."}
            return assets

        @mcp.tool()
        def get_indices_by_type(log_type: str) -> list[str]:
            """
            Get indices matching a specific log type.

            Args:
                log_type: Type of logs to search for (windows, linux, sysmon, security, etc.)

            Returns:
                List of matching index names

            Examples:
                - "windows" - Returns all Windows indices
                - "linux" - Returns all Linux indices
                - "sysmon" - Returns all Sysmon indices
                - "security" - Returns all security log indices
            """
            return self.search_client.get_indices_by_type(log_type)

        @mcp.tool()
        def get_index_metadata(index_pattern: str) -> dict:
            """
            Get metadata for a specific index pattern.

            Args:
                index_pattern: Index name or pattern

            Returns:
                Dictionary containing index metadata (OS type, log source, fields, etc.)

            Example:
                get_index_metadata("winlogbeat-*") returns metadata about Windows event logs
            """
            metadata = self.search_client.get_index_metadata(index_pattern)
            if metadata is None:
                return {"message": f"No metadata found for {index_pattern}. Run discover_all_assets first."}
            return metadata
