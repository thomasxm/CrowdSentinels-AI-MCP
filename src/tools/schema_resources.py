"""Schema introspection tools and MCP resources.

This module provides MCP resources and tools for schema discovery,
field mapping lookups, and schema-aware query building.
"""

import logging
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..clients.common.schemas import (
    SCHEMA_REGISTRY,
    LogSourceSchema,
    detect_schema_from_index,
    get_schema,
    list_schemas,
)
from ..clients.common.schemas.registry import SchemaResolver

logger = logging.getLogger(__name__)


# Schema overview for MCP resource
SCHEMA_OVERVIEW = """
# CrowdSentinel Schema Registry

The schema registry provides field name mappings for different log sources.
Use the appropriate schema to ensure ES|QL queries use correct field names.

## Available Schemas

### Sysmon (schema_id: "sysmon")
- **Index patterns**: `winlogbeat-*`, `sysmon-*`
- **Field prefix**: `winlog.event_data.`
- **Event types**: process_create (1), network_connection (3), file_create (11),
  registry_value_set (13), process_access (10), remote_thread (8), dns_query (22)

### ECS (schema_id: "ecs")
- **Index patterns**: `logs-endpoint.*`, `logs-*`
- **Field prefix**: (none - ECS fields at root)
- **Event types**: process_create, network_connection, file_create, dns_query

### Windows Security (schema_id: "windows_security")
- **Index patterns**: `winlogbeat-*`, `logs-windows.security*`
- **Field prefix**: `winlog.event_data.`
- **Event types**: logon_success (4624), logon_failure (4625),
  process_create (4688), service_install (4697)

## Usage

1. **Auto-detection**: The `hunt_suspicious_process_activity` tool auto-detects
   schemas from index patterns.

2. **Explicit hint**: Pass `schema_hint="sysmon"` to force a specific schema.

3. **Field lookup**: Use `get_field_mapping()` tool to find the actual field name
   for a semantic concept in a specific schema.

## Common Field Mappings

| Semantic Name    | Sysmon                        | ECS               | Windows Security |
|-----------------|-------------------------------|-------------------|------------------|
| source_process  | winlog.event_data.Image       | process.executable| NewProcessName   |
| parent_process  | winlog.event_data.ParentImage | process.parent.executable | - |
| command_line    | winlog.event_data.CommandLine | process.command_line | CommandLine |
| target_process  | winlog.event_data.TargetImage | -                 | -                |
| destination_ip  | winlog.event_data.DestinationIp | destination.ip  | -                |

## MITRE ATT&CK Coverage

The tool automatically detects these techniques based on event types found:
- T1059: Command and Scripting Interpreter (process creation with command line)
- T1055: Process Injection (remote thread creation, process access)
- T1003: OS Credential Dumping (LSASS process access)
- T1112: Modify Registry (registry events)
- T1071: Application Layer Protocol (network connections)
"""


class SchemaTools:
    """MCP tools and resources for schema introspection."""

    def __init__(self, es_client=None):
        """Initialise the schema tools.

        Args:
            es_client: Optional Elasticsearch client for field sampling
        """
        self.resolver = SchemaResolver(es_client)

    def register_tools(self, mcp: FastMCP):
        """Register schema tools and resources with MCP."""

        # =====================================================================
        # MCP Resources
        # =====================================================================

        @mcp.resource("crowdsentinel://schemas")
        def get_schemas_overview():
            """
            Overview of all available log source schemas.

            Read this resource to understand:
            - Available schemas and their index patterns
            - Field mappings between semantic names and actual field names
            - Event types supported by each schema
            - How to use schema-aware tools
            """
            return SCHEMA_OVERVIEW

        @mcp.resource("crowdsentinel://schemas/list")
        def get_schemas_list():
            """
            Machine-readable list of all available schemas.

            Returns JSON with schema details for programmatic use.
            """
            return list_schemas()

        # =====================================================================
        # MCP Tools
        # =====================================================================

        @mcp.tool()
        def list_available_schemas() -> dict[str, Any]:
            """
            List all available log source schemas in the registry.

            Returns summary information about each schema including:
            - Schema ID and name
            - Source type (sysmon, ecs, windows_security)
            - Index patterns the schema matches
            - Supported event types

            Use this to discover available schemas before running queries.

            Example:
                list_available_schemas()
            """
            schemas = list_schemas()
            return {
                "total_schemas": len(schemas),
                "schemas": schemas,
                "usage_hint": "Use schema_hint parameter in hunt_suspicious_process_activity "
                "to specify which schema to use",
            }

        @mcp.tool()
        def get_schema_details(schema_id: str) -> dict[str, Any]:
            """
            Get detailed information about a specific schema.

            Args:
                schema_id: The schema identifier ("sysmon", "ecs", "windows_security")

            Returns:
                Complete schema details including all event types and field mappings

            Example:
                get_schema_details("sysmon")
            """
            schema = get_schema(schema_id)
            if not schema:
                return {
                    "error": f"Schema '{schema_id}' not found",
                    "available_schemas": [s["schema_id"] for s in list_schemas()],
                }

            return {
                "schema_id": schema.schema_id,
                "name": schema.name,
                "description": schema.description,
                "source_type": schema.source_type.value,
                "index_patterns": schema.index_patterns,
                "field_prefix": schema.field_prefix,
                "timestamp_field": schema.timestamp_field,
                "host_field": schema.host_field,
                "event_code_field": schema.event_code_field,
                "event_types": {
                    event_type: {
                        "event_code": defn.event_code,
                        "description": defn.description,
                        "category": defn.category,
                        "fields": defn.fields,
                    }
                    for event_type, defn in schema.event_types.items()
                },
            }

        @mcp.tool()
        def get_field_mapping(
            semantic_field: str, event_type: str, schema_id: str | None = None, index: str | None = None
        ) -> dict[str, Any]:
            """
            Get the actual field name for a semantic field concept.

            Translates semantic field names (like "source_process") to the actual
            field path used in a specific schema (like "winlog.event_data.Image").

            Args:
                semantic_field: The semantic field name (e.g., "source_process",
                    "destination_ip", "command_line")
                event_type: The event type context (e.g., "process_create",
                    "network_connection", "file_create")
                schema_id: Optional explicit schema ID. If not provided, tries
                    to detect from index pattern
                index: Optional index pattern for auto-detection

            Returns:
                The actual field path and mapping details

            Examples:
                # Get field for Sysmon
                get_field_mapping("source_process", "process_create", schema_id="sysmon")
                # Returns: {"field": "winlog.event_data.Image", ...}

                # Auto-detect from index
                get_field_mapping("destination_ip", "network_connection", index="winlogbeat-*")
            """
            # Resolve schema
            schema: LogSourceSchema | None = None
            if schema_id:
                schema = get_schema(schema_id)
            if not schema and index:
                schema = detect_schema_from_index(index)

            if not schema:
                return {
                    "error": "Could not determine schema. Provide schema_id or index.",
                    "available_schemas": [s["schema_id"] for s in list_schemas()],
                }

            # Get the field mapping
            field = schema.get_field(semantic_field, event_type)

            if not field:
                # Get all available fields for this event type
                available_fields = []
                if schema.has_event_type(event_type):
                    event_def = schema.event_types[event_type]
                    available_fields = list(event_def.fields.keys())

                return {
                    "error": f"Field '{semantic_field}' not found for event type '{event_type}'",
                    "schema_id": schema.schema_id,
                    "event_type": event_type,
                    "available_fields": available_fields,
                }

            return {
                "semantic_field": semantic_field,
                "event_type": event_type,
                "schema_id": schema.schema_id,
                "actual_field": field,
                "full_field_path": field,  # Already includes prefix from schema
                "field_prefix": schema.field_prefix,
                "usage_example": f'| WHERE {field} LIKE "*suspicious*"',
            }

        @mcp.tool()
        def detect_schema_for_index(index_pattern: str) -> dict[str, Any]:
            """
            Detect which schema to use for an index pattern.

            Attempts to match the index pattern against known schema patterns.
            Use this to understand which schema will be auto-detected for a query.

            Args:
                index_pattern: The Elasticsearch index pattern (e.g., "winlogbeat-*")

            Returns:
                Detected schema information or available options if no match

            Examples:
                detect_schema_for_index("winlogbeat-*")
                detect_schema_for_index("logs-endpoint.events.process-*")
            """
            schema = detect_schema_from_index(index_pattern)

            if schema:
                return {
                    "detected": True,
                    "index_pattern": index_pattern,
                    "schema_id": schema.schema_id,
                    "schema_name": schema.name,
                    "source_type": schema.source_type.value,
                    "field_prefix": schema.field_prefix,
                    "event_types": list(schema.event_types.keys()),
                }
            return {
                "detected": False,
                "index_pattern": index_pattern,
                "message": "No schema auto-detected. Will fall back to Sysmon schema.",
                "suggestion": "Use schema_hint parameter to specify explicitly.",
                "available_schemas": [
                    {"schema_id": s["schema_id"], "index_patterns": s["index_patterns"]} for s in list_schemas()
                ],
            }

        @mcp.tool()
        def get_event_type_fields(event_type: str, schema_id: str | None = None) -> dict[str, Any]:
            """
            Get all fields available for a specific event type.

            Returns the complete field mapping for an event type, showing
            semantic names and their actual field paths.

            Args:
                event_type: The event type (e.g., "process_create", "network_connection")
                schema_id: Optional schema ID (shows all schemas if not specified)

            Returns:
                Field mappings for the event type across schemas

            Examples:
                # Get fields for specific schema
                get_event_type_fields("process_create", schema_id="sysmon")

                # Compare across all schemas
                get_event_type_fields("process_create")
            """
            if schema_id:
                schema = get_schema(schema_id)
                if not schema:
                    return {
                        "error": f"Schema '{schema_id}' not found",
                        "available_schemas": [s["schema_id"] for s in list_schemas()],
                    }

                if not schema.has_event_type(event_type):
                    return {
                        "error": f"Event type '{event_type}' not supported by schema '{schema_id}'",
                        "available_event_types": list(schema.event_types.keys()),
                    }

                event_def = schema.event_types[event_type]
                return {
                    "event_type": event_type,
                    "schema_id": schema_id,
                    "event_code": event_def.event_code,
                    "description": event_def.description,
                    "category": event_def.category,
                    "fields": event_def.fields,
                }

            # Return for all schemas
            results = {}
            for sid, schema in SCHEMA_REGISTRY.items():
                if schema.has_event_type(event_type):
                    event_def = schema.event_types[event_type]
                    results[sid] = {
                        "event_code": event_def.event_code,
                        "description": event_def.description,
                        "fields": event_def.fields,
                    }

            if not results:
                return {
                    "error": f"Event type '{event_type}' not found in any schema",
                    "available_event_types": {
                        sid: list(schema.event_types.keys()) for sid, schema in SCHEMA_REGISTRY.items()
                    },
                }

            return {"event_type": event_type, "schemas_supporting": list(results.keys()), "mappings": results}
