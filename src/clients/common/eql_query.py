"""EQL (Event Query Language) Client for threat hunting and incident response."""

from src.clients.base import SearchClientBase
from src.clients.common.field_mapper import FieldMapper


class EQLQueryClient(SearchClientBase):
    """Client for executing EQL queries for threat hunting."""

    def __init__(self, config: dict, engine_type: str = "elasticsearch"):
        """
        Initialise the EQL query client.

        Args:
            config: Configuration dictionary with connection parameters
            engine_type: Backend type (elasticsearch or opensearch)
        """
        super().__init__(config, engine_type)
        # Initialise FieldMapper for field name substitution
        self._field_mapper: FieldMapper | None = None

    @property
    def field_mapper(self) -> FieldMapper:
        """Get or create the FieldMapper instance with ES client reference."""
        if self._field_mapper is None:
            self._field_mapper = FieldMapper(client=self.client)
        return self._field_mapper

    def eql_search(
        self,
        index: str,
        query: str,
        size: int = 100,
        filter_query: dict | None = None,
        timestamp_field: str = "@timestamp",
        start_time: str | None = None,
        end_time: str | None = None,
        field_substitution: bool = True,
    ) -> dict:
        """
        Execute an EQL query for threat hunting with automatic field substitution.

        Field substitution automatically adapts ECS field names to the actual
        field names in the target index (e.g., process.name -> winlog.event_data.Image).

        Args:
            index: Index pattern to search
            query: EQL query string (must be a valid EQL query, not just "any where ...")
            size: Maximum number of results
            filter_query: Optional filter to apply before EQL query
            timestamp_field: Timestamp field name
            start_time: Optional start time (e.g., "now-1h", "2024-01-01T00:00:00")
            end_time: Optional end time (defaults to "now")
            field_substitution: If True, substitute ECS fields with index-specific fields

        Returns:
            EQL query results with events, metadata, and field substitutions
        """
        field_substitutions = {}

        # Apply field substitution if enabled
        if field_substitution:
            available_fields = self.field_mapper.get_index_fields(index)
            if available_fields:
                # Get substitution report for transparency
                sub_report = self.field_mapper.get_substitution_report(query, available_fields)
                field_substitutions = sub_report.get("substitutions", {})

                # Apply substitutions to the query
                query = self.field_mapper.substitute_fields_eql(query, available_fields)

        # Build time filter if specified
        if start_time or end_time:
            time_filter = {"range": {timestamp_field: {}}}

            if start_time:
                time_filter["range"][timestamp_field]["gte"] = start_time
            if end_time:
                time_filter["range"][timestamp_field]["lte"] = end_time

            # Combine with existing filter
            if filter_query:
                # Merge filters
                if "bool" not in filter_query:
                    filter_query = {"bool": {"must": [filter_query]}}
                if "must" not in filter_query["bool"]:
                    filter_query["bool"]["must"] = []
                elif not isinstance(filter_query["bool"]["must"], list):
                    filter_query["bool"]["must"] = [filter_query["bool"]["must"]]

                filter_query["bool"]["must"].append(time_filter)
            else:
                filter_query = time_filter

        body = {"query": query, "size": size, "timestamp_field": timestamp_field}

        if filter_query:
            body["filter"] = filter_query

        try:
            if self.engine_type == "elasticsearch":
                response = self.client.eql.search(index=index, body=body)
            else:
                # OpenSearch might not support EQL, fall back to general client
                response = self.general_client.request(method="POST", path=f"/{index}/_eql/search", body=body)

            # Format response to be consistent with regular search
            # EQL returns hits in response["hits"]["events"]
            if "hits" in response:
                events = response["hits"].get("events", [])
                total_count = response["hits"].get("total", {})
                if isinstance(total_count, dict):
                    total_hits = total_count.get("value", len(events))
                else:
                    total_hits = total_count

                formatted_response = {
                    "total_hits": total_hits,
                    "events": events,
                    "execution_time_ms": response.get("took", 0),
                    "raw_response": response,  # Keep raw response for advanced use
                    # WORKFLOW HINT: Guide AI to use analysis tools
                    "workflow_hint": {
                        "next_step": "analyze_search_results",
                        "instruction": (
                            "MANDATORY: Use analyze_search_results() on these EQL results to "
                            "extract IoCs, map MITRE ATT&CK techniques, and get recommendations. "
                            "Then use analyze_kill_chain_stage() to position in kill chain."
                        ),
                        "final_step": "Use generate_investigation_report() before presenting findings",
                    },
                }

                # Add field substitution metadata
                if field_substitutions:
                    formatted_response["field_substitutions"] = {
                        "enabled": True,
                        "substitutions": field_substitutions,
                        "count": len(field_substitutions),
                    }
                elif field_substitution:
                    formatted_response["field_substitutions"] = {
                        "enabled": True,
                        "substitutions": {},
                        "count": 0,
                        "note": "No field substitutions needed - fields already match",
                    }

                return formatted_response
            return response

        except Exception as e:
            self.logger.error(f"EQL search failed: {e}")
            raise

    def eql_delete(self, eql_search_id: str) -> dict:
        """Delete an async EQL search."""
        try:
            return self.client.eql.delete(id=eql_search_id)
        except Exception as e:
            self.logger.error(f"Failed to delete EQL search: {e}")
            raise

    def get_eql_status(self, eql_search_id: str) -> dict:
        """Get status of an async EQL search."""
        try:
            return self.client.eql.get_status(id=eql_search_id)
        except Exception as e:
            self.logger.error(f"Failed to get EQL status: {e}")
            raise
