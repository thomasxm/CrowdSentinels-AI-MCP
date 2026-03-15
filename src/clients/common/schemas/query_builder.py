"""Schema-aware query builder for ES|QL queries.

This module provides query builders that generate ES|QL queries using
the correct field names based on the target schema.
"""

import logging
from dataclasses import dataclass
from typing import Any

from .base import LogSourceSchema

logger = logging.getLogger(__name__)


@dataclass
class QueryResult:
    """Result of building a query."""
    query: str
    event_type: str
    event_code: str
    fields_used: list[str]
    description: str


class SchemaAwareQueryBuilder:
    """Builds ES|QL queries using schema-appropriate field names.

    This class generates ES|QL queries for various hunting scenarios,
    automatically substituting field names based on the target schema.
    """

    def __init__(
        self,
        schema: LogSourceSchema,
        index: str,
        max_results: int = 100
    ):
        """Initialise the query builder.

        Args:
            schema: The log source schema to use for field mapping
            index: The index pattern to query
            max_results: Maximum results per query
        """
        self.schema = schema
        self.index = index
        self.max_results = max_results

    def build_process_bounds_query(self, process_name: str) -> QueryResult:
        """Build query to find process creation time bounds.

        Args:
            process_name: Name or path pattern of the process

        Returns:
            QueryResult with the ES|QL query
        """
        process_field = self.schema.get_field("source_process", "process_create")
        event_code = self.schema.get_event_code("process_create")
        host_field = self.schema.host_field
        event_code_field = self.schema.event_code_field
        timestamp_field = self.schema.timestamp_field

        if not process_field or not event_code:
            raise ValueError(
                f"Schema '{self.schema.schema_id}' does not support process_create"
            )

        query = f'''FROM {self.index}
| WHERE {event_code_field} == "{event_code}"
  AND {process_field} LIKE "*{process_name}*"
| STATS
    start_time = MIN({timestamp_field}),
    end_time = MAX({timestamp_field}),
    hosts = VALUES({host_field}),
    count = COUNT(*)
| LIMIT 1'''

        return QueryResult(
            query=query,
            event_type="process_create",
            event_code=event_code,
            fields_used=[process_field, event_code_field, host_field, timestamp_field],
            description=f"Find time bounds for process '{process_name}'"
        )

    def build_process_terminate_query(
        self,
        process_name: str,
        host: str | None = None,
        start_time: str | None = None,
        end_time: str | None = None
    ) -> QueryResult:
        """Build query for process termination events.

        Args:
            process_name: Name or path pattern of the process
            host: Optional hostname filter
            start_time: Optional start time filter
            end_time: Optional end time filter

        Returns:
            QueryResult with the ES|QL query
        """
        process_field = self.schema.get_field("source_process", "process_terminate")
        event_code = self.schema.get_event_code("process_terminate")
        host_field = self.schema.host_field
        event_code_field = self.schema.event_code_field
        timestamp_field = self.schema.timestamp_field

        if not process_field or not event_code:
            raise ValueError(
                f"Schema '{self.schema.schema_id}' does not support process_terminate"
            )

        # Build WHERE clause
        conditions = [
            f'{event_code_field} == "{event_code}"',
            f'{process_field} LIKE "*{process_name}*"'
        ]

        if host:
            conditions.append(f'{host_field} == "{host}"')
        if start_time:
            conditions.append(f'{timestamp_field} >= "{start_time}"')
        if end_time:
            conditions.append(f'{timestamp_field} <= "{end_time}"')

        where_clause = "\n  AND ".join(conditions)

        query = f'''FROM {self.index}
| WHERE {where_clause}
| KEEP {timestamp_field}, {process_field}, {host_field}
| SORT {timestamp_field}
| LIMIT {self.max_results}'''

        return QueryResult(
            query=query,
            event_type="process_terminate",
            event_code=event_code,
            fields_used=[process_field, event_code_field, host_field, timestamp_field],
            description=f"Find termination events for process '{process_name}'"
        )

    def build_child_processes_query(
        self,
        parent_process_name: str,
        host: str,
        start_time: str,
        end_time: str
    ) -> QueryResult:
        """Build query for child processes spawned by a process.

        Args:
            parent_process_name: Name or path pattern of the parent process
            host: Hostname filter
            start_time: Start time filter
            end_time: End time filter

        Returns:
            QueryResult with the ES|QL query
        """
        parent_field = self.schema.get_field("parent_process", "process_create")
        process_field = self.schema.get_field("source_process", "process_create")
        cmd_field = self.schema.get_field("command_line", "process_create")
        event_code = self.schema.get_event_code("process_create")
        host_field = self.schema.host_field
        event_code_field = self.schema.event_code_field
        timestamp_field = self.schema.timestamp_field

        if not parent_field or not event_code:
            raise ValueError(
                f"Schema '{self.schema.schema_id}' does not support parent process tracking"
            )

        # Build KEEP clause with available fields
        keep_fields = [timestamp_field, process_field, host_field]
        if cmd_field:
            keep_fields.append(cmd_field)
        if parent_field:
            keep_fields.append(parent_field)

        query = f'''FROM {self.index}
| WHERE {event_code_field} == "{event_code}"
  AND {host_field} == "{host}"
  AND {timestamp_field} >= "{start_time}"
  AND {timestamp_field} <= "{end_time}"
  AND {parent_field} LIKE "*{parent_process_name}*"
| KEEP {", ".join(keep_fields)}
| SORT {timestamp_field}
| LIMIT {self.max_results}'''

        return QueryResult(
            query=query,
            event_type="process_create",
            event_code=event_code,
            fields_used=keep_fields,
            description=f"Find child processes of '{parent_process_name}'"
        )

    def build_network_connections_query(
        self,
        process_name: str,
        host: str,
        start_time: str,
        end_time: str
    ) -> QueryResult:
        """Build query for network connections made by a process.

        Args:
            process_name: Name or path pattern of the process
            host: Hostname filter
            start_time: Start time filter
            end_time: End time filter

        Returns:
            QueryResult with the ES|QL query
        """
        process_field = self.schema.get_field("source_process", "network_connection")
        dest_ip_field = self.schema.get_field("destination_ip", "network_connection")
        dest_port_field = self.schema.get_field("destination_port", "network_connection")
        protocol_field = self.schema.get_field("protocol", "network_connection")
        event_code = self.schema.get_event_code("network_connection")
        host_field = self.schema.host_field
        event_code_field = self.schema.event_code_field
        timestamp_field = self.schema.timestamp_field

        if not process_field or not event_code:
            raise ValueError(
                f"Schema '{self.schema.schema_id}' does not support network_connection"
            )

        # Build KEEP clause with available fields
        keep_fields = [timestamp_field, process_field, host_field]
        if dest_ip_field:
            keep_fields.append(dest_ip_field)
        if dest_port_field:
            keep_fields.append(dest_port_field)
        if protocol_field:
            keep_fields.append(protocol_field)

        query = f'''FROM {self.index}
| WHERE {event_code_field} == "{event_code}"
  AND {host_field} == "{host}"
  AND {timestamp_field} >= "{start_time}"
  AND {timestamp_field} <= "{end_time}"
  AND {process_field} LIKE "*{process_name}*"
| KEEP {", ".join(keep_fields)}
| SORT {timestamp_field}
| LIMIT {self.max_results}'''

        return QueryResult(
            query=query,
            event_type="network_connection",
            event_code=event_code,
            fields_used=keep_fields,
            description=f"Find network connections by '{process_name}'"
        )

    def build_file_operations_query(
        self,
        process_name: str,
        host: str,
        start_time: str,
        end_time: str
    ) -> QueryResult:
        """Build query for file operations by a process.

        Args:
            process_name: Name or path pattern of the process
            host: Hostname filter
            start_time: Start time filter
            end_time: End time filter

        Returns:
            QueryResult with the ES|QL query
        """
        process_field = self.schema.get_field("source_process", "file_create")
        target_file_field = self.schema.get_field("target_filename", "file_create")
        event_code = self.schema.get_event_code("file_create")
        host_field = self.schema.host_field
        event_code_field = self.schema.event_code_field
        timestamp_field = self.schema.timestamp_field

        if not process_field or not event_code:
            raise ValueError(
                f"Schema '{self.schema.schema_id}' does not support file_create"
            )

        # Build KEEP clause with available fields
        keep_fields = [timestamp_field, process_field, host_field]
        if target_file_field:
            keep_fields.append(target_file_field)

        query = f'''FROM {self.index}
| WHERE {event_code_field} == "{event_code}"
  AND {host_field} == "{host}"
  AND {timestamp_field} >= "{start_time}"
  AND {timestamp_field} <= "{end_time}"
  AND {process_field} LIKE "*{process_name}*"
| KEEP {", ".join(keep_fields)}
| SORT {timestamp_field}
| LIMIT {self.max_results}'''

        return QueryResult(
            query=query,
            event_type="file_create",
            event_code=event_code,
            fields_used=keep_fields,
            description=f"Find file operations by '{process_name}'"
        )

    def build_registry_operations_query(
        self,
        process_name: str,
        host: str,
        start_time: str,
        end_time: str
    ) -> QueryResult:
        """Build query for registry operations by a process.

        Args:
            process_name: Name or path pattern of the process
            host: Hostname filter
            start_time: Start time filter
            end_time: End time filter

        Returns:
            QueryResult with the ES|QL query
        """
        # Try registry_value_set first (more common), then registry_create_delete
        process_field = self.schema.get_field("source_process", "registry_value_set")
        target_object_field = self.schema.get_field("target_object", "registry_value_set")
        details_field = self.schema.get_field("details", "registry_value_set")
        event_code = self.schema.get_event_code("registry_value_set")

        if not process_field:
            process_field = self.schema.get_field("source_process", "registry_create_delete")
            target_object_field = self.schema.get_field("target_object", "registry_create_delete")
            event_code = self.schema.get_event_code("registry_create_delete")

        if not process_field or not event_code:
            raise ValueError(
                f"Schema '{self.schema.schema_id}' does not support registry events"
            )

        host_field = self.schema.host_field
        event_code_field = self.schema.event_code_field
        timestamp_field = self.schema.timestamp_field

        # Build KEEP clause with available fields
        keep_fields = [timestamp_field, process_field, host_field, event_code_field]
        if target_object_field:
            keep_fields.append(target_object_field)
        if details_field:
            keep_fields.append(details_field)

        # Query for multiple registry event codes (12, 13, 14 for Sysmon)
        query = f'''FROM {self.index}
| WHERE {event_code_field} IN ("12", "13", "14")
  AND {host_field} == "{host}"
  AND {timestamp_field} >= "{start_time}"
  AND {timestamp_field} <= "{end_time}"
  AND {process_field} LIKE "*{process_name}*"
| KEEP {", ".join(keep_fields)}
| SORT {timestamp_field}
| LIMIT {self.max_results}'''

        return QueryResult(
            query=query,
            event_type="registry",
            event_code="12,13,14",
            fields_used=keep_fields,
            description=f"Find registry operations by '{process_name}'"
        )

    def build_process_access_query(
        self,
        process_name: str,
        host: str,
        start_time: str,
        end_time: str,
        as_source: bool = True,
        as_target: bool = True
    ) -> QueryResult:
        """Build query for process access events (Event ID 10).

        This is critical for detecting credential dumping (LSASS access).

        Args:
            process_name: Name or path pattern of the process
            host: Hostname filter
            start_time: Start time filter
            end_time: End time filter
            as_source: Include events where process is the accessor
            as_target: Include events where process is being accessed

        Returns:
            QueryResult with the ES|QL query
        """
        source_field = self.schema.get_field("source_process", "process_access")
        target_field = self.schema.get_field("target_process", "process_access")
        granted_access_field = self.schema.get_field("granted_access", "process_access")
        call_trace_field = self.schema.get_field("call_trace", "process_access")
        event_code = self.schema.get_event_code("process_access")

        if not source_field or not target_field or not event_code:
            raise ValueError(
                f"Schema '{self.schema.schema_id}' does not support process_access"
            )

        host_field = self.schema.host_field
        event_code_field = self.schema.event_code_field
        timestamp_field = self.schema.timestamp_field

        # Build process filter
        process_conditions = []
        if as_source:
            process_conditions.append(f'{source_field} LIKE "*{process_name}*"')
        if as_target:
            process_conditions.append(f'{target_field} LIKE "*{process_name}*"')

        if not process_conditions:
            raise ValueError("Must specify as_source or as_target")

        process_filter = " OR ".join(process_conditions)
        if len(process_conditions) > 1:
            process_filter = f"({process_filter})"

        # Build KEEP clause with available fields
        keep_fields = [timestamp_field, source_field, target_field, host_field]
        if granted_access_field:
            keep_fields.append(granted_access_field)
        if call_trace_field:
            keep_fields.append(call_trace_field)

        query = f'''FROM {self.index}
| WHERE {event_code_field} == "{event_code}"
  AND {host_field} == "{host}"
  AND {timestamp_field} >= "{start_time}"
  AND {timestamp_field} <= "{end_time}"
  AND {process_filter}
| KEEP {", ".join(keep_fields)}
| SORT {timestamp_field}
| LIMIT {self.max_results}'''

        return QueryResult(
            query=query,
            event_type="process_access",
            event_code=event_code,
            fields_used=keep_fields,
            description=f"Find process access events for '{process_name}'"
        )

    def build_remote_thread_query(
        self,
        process_name: str,
        host: str,
        start_time: str,
        end_time: str,
        as_source: bool = True,
        as_target: bool = True
    ) -> QueryResult:
        """Build query for remote thread creation events (Event ID 8).

        This is critical for detecting process injection.

        Args:
            process_name: Name or path pattern of the process
            host: Hostname filter
            start_time: Start time filter
            end_time: End time filter
            as_source: Include events where process creates the thread
            as_target: Include events where process receives the thread

        Returns:
            QueryResult with the ES|QL query
        """
        source_field = self.schema.get_field("source_process", "remote_thread")
        target_field = self.schema.get_field("target_process", "remote_thread")
        start_function_field = self.schema.get_field("start_function", "remote_thread")
        start_address_field = self.schema.get_field("start_address", "remote_thread")
        event_code = self.schema.get_event_code("remote_thread")

        if not source_field or not target_field or not event_code:
            raise ValueError(
                f"Schema '{self.schema.schema_id}' does not support remote_thread"
            )

        host_field = self.schema.host_field
        event_code_field = self.schema.event_code_field
        timestamp_field = self.schema.timestamp_field

        # Build process filter
        process_conditions = []
        if as_source:
            process_conditions.append(f'{source_field} LIKE "*{process_name}*"')
        if as_target:
            process_conditions.append(f'{target_field} LIKE "*{process_name}*"')

        if not process_conditions:
            raise ValueError("Must specify as_source or as_target")

        process_filter = " OR ".join(process_conditions)
        if len(process_conditions) > 1:
            process_filter = f"({process_filter})"

        # Build KEEP clause with available fields
        keep_fields = [timestamp_field, source_field, target_field, host_field]
        if start_function_field:
            keep_fields.append(start_function_field)
        if start_address_field:
            keep_fields.append(start_address_field)

        query = f'''FROM {self.index}
| WHERE {event_code_field} == "{event_code}"
  AND {host_field} == "{host}"
  AND {timestamp_field} >= "{start_time}"
  AND {timestamp_field} <= "{end_time}"
  AND {process_filter}
| KEEP {", ".join(keep_fields)}
| SORT {timestamp_field}
| LIMIT {self.max_results}'''

        return QueryResult(
            query=query,
            event_type="remote_thread",
            event_code=event_code,
            fields_used=keep_fields,
            description=f"Find remote thread events for '{process_name}'"
        )

    def build_dns_query(
        self,
        process_name: str,
        host: str,
        start_time: str,
        end_time: str
    ) -> QueryResult:
        """Build query for DNS queries made by a process.

        Args:
            process_name: Name or path pattern of the process
            host: Hostname filter
            start_time: Start time filter
            end_time: End time filter

        Returns:
            QueryResult with the ES|QL query
        """
        process_field = self.schema.get_field("source_process", "dns_query")
        query_name_field = self.schema.get_field("query_name", "dns_query")
        query_results_field = self.schema.get_field("query_results", "dns_query")
        event_code = self.schema.get_event_code("dns_query")

        if not process_field or not event_code:
            raise ValueError(
                f"Schema '{self.schema.schema_id}' does not support dns_query"
            )

        host_field = self.schema.host_field
        event_code_field = self.schema.event_code_field
        timestamp_field = self.schema.timestamp_field

        # Build KEEP clause with available fields
        keep_fields = [timestamp_field, process_field, host_field]
        if query_name_field:
            keep_fields.append(query_name_field)
        if query_results_field:
            keep_fields.append(query_results_field)

        query = f'''FROM {self.index}
| WHERE {event_code_field} == "{event_code}"
  AND {host_field} == "{host}"
  AND {timestamp_field} >= "{start_time}"
  AND {timestamp_field} <= "{end_time}"
  AND {process_field} LIKE "*{process_name}*"
| KEEP {", ".join(keep_fields)}
| SORT {timestamp_field}
| LIMIT {self.max_results}'''

        return QueryResult(
            query=query,
            event_type="dns_query",
            event_code=event_code,
            fields_used=keep_fields,
            description=f"Find DNS queries by '{process_name}'"
        )

    def build_host_activity_query(
        self,
        host: str,
        start_time: str,
        end_time: str,
        event_codes: list[str] | None = None
    ) -> QueryResult:
        """Build query for all activity on a host during a time window.

        Args:
            host: Hostname filter
            start_time: Start time filter
            end_time: End time filter
            event_codes: Optional list of event codes to filter

        Returns:
            QueryResult with the ES|QL query
        """
        host_field = self.schema.host_field
        event_code_field = self.schema.event_code_field
        timestamp_field = self.schema.timestamp_field

        conditions = [
            f'{host_field} == "{host}"',
            f'{timestamp_field} >= "{start_time}"',
            f'{timestamp_field} <= "{end_time}"'
        ]

        if event_codes:
            codes_str = ", ".join(f'"{c}"' for c in event_codes)
            conditions.append(f'{event_code_field} IN ({codes_str})')

        where_clause = "\n  AND ".join(conditions)

        query = f'''FROM {self.index}
| WHERE {where_clause}
| SORT {timestamp_field}
| LIMIT {self.max_results}'''

        return QueryResult(
            query=query,
            event_type="all",
            event_code="*" if not event_codes else ",".join(event_codes),
            fields_used=[host_field, event_code_field, timestamp_field],
            description=f"Find all activity on host '{host}'"
        )

    def get_supported_event_types(self) -> list[str]:
        """Get list of event types supported by this schema."""
        return self.schema.list_event_types()

    def get_schema_info(self) -> dict[str, Any]:
        """Get information about the current schema."""
        return {
            "schema_id": self.schema.schema_id,
            "name": self.schema.name,
            "source_type": self.schema.source_type.value,
            "index": self.index,
            "field_prefix": self.schema.field_prefix,
            "event_types": self.get_supported_event_types(),
            "event_code_field": self.schema.event_code_field,
            "event_code_alternatives": self.schema.event_code_alternatives,
        }

    def build_event_code_condition(
        self,
        event_code: str,
        use_alternatives: bool = False
    ) -> str:
        """Build event code filter condition.

        Args:
            event_code: The event code value to match
            use_alternatives: If True, generates OR condition for all alternatives

        Returns:
            ES|QL WHERE condition string

        Example:
            With use_alternatives=False: 'event.code == "1"'
            With use_alternatives=True:  '(event.code == "1" OR winlog.event_id == "1")'
        """
        primary_field = self.schema.event_code_field

        if not use_alternatives or not self.schema.event_code_alternatives:
            return f'{primary_field} == "{event_code}"'

        # Build OR condition for all possible field names
        all_fields = self.schema.get_event_code_fields()
        conditions = [f'{field} == "{event_code}"' for field in all_fields]

        if len(conditions) == 1:
            return conditions[0]

        return f"({' OR '.join(conditions)})"

    def build_event_codes_in_condition(
        self,
        event_codes: list[str],
        use_alternatives: bool = False
    ) -> str:
        """Build event code IN filter condition for multiple codes.

        Args:
            event_codes: List of event codes to match
            use_alternatives: If True, generates OR condition for all alternatives

        Returns:
            ES|QL WHERE condition string

        Example:
            With use_alternatives=False: 'event.code IN ("12", "13", "14")'
            With use_alternatives=True:  '(event.code IN ("12", "13", "14") OR winlog.event_id IN ("12", "13", "14"))'
        """
        primary_field = self.schema.event_code_field
        codes_str = ", ".join(f'"{c}"' for c in event_codes)

        if not use_alternatives or not self.schema.event_code_alternatives:
            return f'{primary_field} IN ({codes_str})'

        # Build OR condition for all possible field names
        all_fields = self.schema.get_event_code_fields()
        conditions = [f'{field} IN ({codes_str})' for field in all_fields]

        if len(conditions) == 1:
            return conditions[0]

        return f"({' OR '.join(conditions)})"
