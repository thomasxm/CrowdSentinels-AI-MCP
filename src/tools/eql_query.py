"""EQL Query Tools for threat hunting with Event Query Language."""
from typing import Dict, Optional
from fastmcp import FastMCP


class EQLQueryTools:
    def __init__(self, search_client):
        self.search_client = search_client

    def register_tools(self, mcp: FastMCP):
        @mcp.tool()
        def eql_search(index: str, query: str, size: int = 100,
                      filter_query: Optional[Dict] = None,
                      timestamp_field: str = "@timestamp") -> Dict:
            """
            Execute an EQL (Event Query Language) query for advanced threat hunting.
            EQL is designed for event-based data and is excellent for detecting
            attack patterns and sequences.

            Args:
                index: Index pattern to search (e.g., "winlogbeat-*")
                query: EQL query string (e.g., 'process where process.name == "regsvr32.exe"')
                size: Maximum number of results to return (default: 100)
                filter_query: Optional Elasticsearch filter to apply before EQL query
                timestamp_field: Timestamp field name (default: "@timestamp")

            Returns:
                EQL query results with matching events

            Examples:
                1. Find suspicious process execution:
                   query: 'process where process.name == "powershell.exe"'

                2. Find process creation followed by network connection:
                   query: 'sequence [process where process.name == "cmd.exe"]
                           [network where destination.port == 443]'

                3. Find registry modifications:
                   query: 'registry where registry.path == "*\\\\Run\\\\*"'
            """
            return self.search_client.eql_search(
                index=index,
                query=query,
                size=size,
                filter_query=filter_query,
                timestamp_field=timestamp_field
            )

        @mcp.tool()
        def eql_delete(eql_search_id: str) -> Dict:
            """
            Delete an async EQL search by ID.

            Args:
                eql_search_id: The ID of the EQL search to delete

            Returns:
                Deletion acknowledgement
            """
            return self.search_client.eql_delete(eql_search_id)

        @mcp.tool()
        def eql_get_status(eql_search_id: str) -> Dict:
            """
            Get the status of an async EQL search.

            Args:
                eql_search_id: The ID of the EQL search

            Returns:
                Status information for the EQL search
            """
            return self.search_client.get_eql_status(eql_search_id)
