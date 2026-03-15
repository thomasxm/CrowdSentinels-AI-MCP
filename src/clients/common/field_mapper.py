"""Field Mapper for adapting queries to different log schemas.

This module provides field name substitution to make hunting queries work with
different log formats (e.g., ECS vs winlogbeat vs CEF).
"""
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)


class FieldMapper:
    """Maps ECS field names to actual field names in target indices.

    Supports field substitution for:
    - ES|QL queries
    - EQL queries
    - Lucene queries

    Field aliases are defined from ECS (Elastic Common Schema) to common
    alternative field names found in different log sources.
    """

    # ECS field to alternative field mappings
    # Format: "ecs_field": ["alternative1", "alternative2", ...]
    # Order matters - first matching alternative is used
    FIELD_ALIASES: dict[str, list[str]] = {
        # Process fields
        "process.name": [
            "winlog.event_data.Image",
            "winlog.event_data.NewProcessName",
            "process.executable",
            "ProcessName",
        ],
        "process.executable": [
            "winlog.event_data.Image",
            "winlog.event_data.NewProcessName",
            "process.name",
        ],
        "process.command_line": [
            "winlog.event_data.CommandLine",
            "process.args",
            "CommandLine",
        ],
        "process.args": [
            "winlog.event_data.CommandLine",
            "process.command_line",
        ],
        "process.pid": [
            "winlog.event_data.ProcessId",
            "winlog.event_data.NewProcessId",
            "ProcessId",
        ],
        "process.parent.name": [
            "winlog.event_data.ParentImage",
            "winlog.event_data.ParentProcessName",
            "ParentProcessName",
        ],
        "process.parent.executable": [
            "winlog.event_data.ParentImage",
            "process.parent.name",
        ],
        "process.parent.command_line": [
            "winlog.event_data.ParentCommandLine",
        ],
        "process.parent.pid": [
            "winlog.event_data.ParentProcessId",
            "ParentProcessId",
        ],
        "process.hash.sha256": [
            "winlog.event_data.Hashes",
            "file.hash.sha256",
        ],
        "process.hash.md5": [
            "winlog.event_data.Hashes",
            "file.hash.md5",
        ],

        # User fields
        "user.name": [
            "winlog.event_data.User",
            "winlog.event_data.TargetUserName",
            "winlog.event_data.SubjectUserName",
            "UserName",
            "user",
        ],
        "user.id": [
            "winlog.event_data.TargetUserSid",
            "winlog.event_data.SubjectUserSid",
            "UserSid",
        ],
        "user.domain": [
            "winlog.event_data.TargetDomainName",
            "winlog.event_data.SubjectDomainName",
            "Domain",
        ],

        # Host fields
        "host.name": [
            "host.hostname",
            "agent.hostname",
            "ComputerName",
            "hostname",
        ],
        "host.hostname": [
            "host.name",
            "agent.hostname",
            "ComputerName",
        ],
        "host.ip": [
            "host.ipaddress",
            "IpAddress",
        ],
        "host.os.type": [
            "host.os.platform",
            "host.os.family",
        ],

        # Network fields
        "source.ip": [
            "winlog.event_data.SourceIp",
            "winlog.event_data.IpAddress",
            "sourceAddress",
            "src_ip",
            "SourceIP",
        ],
        "source.port": [
            "winlog.event_data.SourcePort",
            "sourcePort",
            "src_port",
        ],
        "destination.ip": [
            "winlog.event_data.DestinationIp",
            "destinationAddress",
            "dst_ip",
            "DestinationIP",
        ],
        "destination.port": [
            "winlog.event_data.DestinationPort",
            "destinationPort",
            "dst_port",
        ],

        # File fields
        "file.path": [
            "winlog.event_data.TargetFilename",
            "winlog.event_data.ObjectName",
            "file.target.path",
            "FilePath",
        ],
        "file.name": [
            "winlog.event_data.TargetFilename",
            "FileName",
        ],
        "file.hash.sha256": [
            "winlog.event_data.Hashes",
            "process.hash.sha256",
        ],

        # Registry fields
        "registry.path": [
            "winlog.event_data.TargetObject",
            "winlog.event_data.ObjectName",
            "RegistryKey",
        ],
        "registry.key": [
            "winlog.event_data.TargetObject",
        ],
        "registry.value": [
            "winlog.event_data.Details",
        ],

        # Event fields
        "event.code": [
            "winlog.event_id",
            "EventID",
            "eventId",
        ],
        "event.action": [
            "winlog.event_data.Action",
            "Action",
        ],
        "event.category": [
            "winlog.event_data.Category",
            "Category",
        ],
        "event.type": [
            "winlog.event_data.Type",
        ],

        # DNS fields
        "dns.question.name": [
            "winlog.event_data.QueryName",
            "query",
            "QueryName",
        ],
        "dns.answers.data": [
            "winlog.event_data.QueryResults",
        ],

        # Service fields
        "service.name": [
            "winlog.event_data.ServiceName",
            "ServiceName",
        ],

        # Agent fields
        "agent.id": [
            "agent.name",
            "beat.hostname",
        ],
    }

    def __init__(self, client: Any | None = None):
        """
        Initialise the FieldMapper.

        Args:
            client: Optional Elasticsearch client for fetching index mappings
        """
        self.client = client
        self._field_cache: dict[str, set[str]] = {}  # Cache index field mappings
        self.logger = logging.getLogger(__name__)

    def get_index_fields(self, index: str) -> set[str]:
        """
        Get all field names from an index's mapping.

        Args:
            index: Index name or pattern

        Returns:
            Set of field names in the index
        """
        # Check cache first
        if index in self._field_cache:
            return self._field_cache[index]

        if not self.client:
            return set()

        try:
            # Handle wildcards by getting first matching index
            if "*" in index:
                # Get actual indices matching the pattern
                indices = self.client.cat.indices(index=index, format="json", h="index")
                if not indices:
                    return set()
                # Use first non-empty index
                for idx_info in indices:
                    idx_name = idx_info.get("index", "")
                    if not idx_name.startswith("."):
                        index = idx_name
                        break

            mapping = self.client.indices.get_mapping(index=index)

            # Extract all fields recursively
            fields = set()
            for idx_name, idx_mapping in mapping.items():
                self._extract_fields_recursive(
                    idx_mapping.get("mappings", {}),
                    "",
                    fields
                )

            # Cache the result
            self._field_cache[index] = fields
            return fields

        except Exception as e:
            self.logger.warning(f"Failed to get index fields for {index}: {e}")
            return set()

    def _extract_fields_recursive(
        self,
        obj: dict,
        prefix: str,
        fields: set[str]
    ) -> None:
        """Recursively extract field names from mapping."""
        if "properties" in obj:
            for field_name, field_def in obj["properties"].items():
                full_name = f"{prefix}{field_name}" if prefix else field_name
                fields.add(full_name)
                if isinstance(field_def, dict):
                    self._extract_fields_recursive(
                        field_def,
                        f"{full_name}.",
                        fields
                    )

    def find_substitute(
        self,
        ecs_field: str,
        available_fields: set[str],
        prefer_winlog: bool = True
    ) -> str | None:
        """
        Find a substitute field name for an ECS field.

        For winlogbeat indices, ECS fields may exist in the mapping but contain
        no data - the actual data is in winlog.event_data.* fields. When
        prefer_winlog=True, we substitute to winlog.* fields even if ECS fields
        exist in the mapping.

        Args:
            ecs_field: ECS field name to substitute
            available_fields: Set of fields available in target index
            prefer_winlog: If True, prefer winlog.* fields over ECS fields

        Returns:
            Substitute field name, or None if no substitute found
        """
        # Check if we have winlog-specific aliases for this field
        if ecs_field in self.FIELD_ALIASES:
            winlog_aliases = [
                a for a in self.FIELD_ALIASES[ecs_field]
                if a.startswith("winlog.")
            ]

            # If prefer_winlog and we have winlog aliases, check them first
            if prefer_winlog and winlog_aliases:
                for alias in winlog_aliases:
                    if alias in available_fields:
                        return alias

        # If field already exists and we didn't find a preferred winlog alias
        if ecs_field in available_fields:
            return None

        # Check all aliases as fallback
        if ecs_field in self.FIELD_ALIASES:
            for alias in self.FIELD_ALIASES[ecs_field]:
                if alias in available_fields:
                    return alias

        return None

    def substitute_fields_esql(
        self,
        query: str,
        available_fields: set[str],
        enabled: bool = True
    ) -> str:
        """
        Substitute ECS field names in an ES|QL query.

        Args:
            query: Original ES|QL query
            available_fields: Set of fields available in target index
            enabled: If False, return query unchanged

        Returns:
            Query with substituted field names
        """
        if not enabled or not available_fields:
            return query

        substitutions = {}

        # Find all ECS fields that need substitution
        for ecs_field in self.FIELD_ALIASES.keys():
            if ecs_field in query:
                substitute = self.find_substitute(ecs_field, available_fields)
                if substitute:
                    substitutions[ecs_field] = substitute

        if not substitutions:
            return query

        # Apply substitutions (longest field names first to avoid partial matches)
        result = query
        for ecs_field in sorted(substitutions.keys(), key=len, reverse=True):
            substitute = substitutions[ecs_field]
            # Use word boundaries to avoid partial replacements
            # Match field name followed by space, operator, comma, or end
            pattern = rf'\b{re.escape(ecs_field)}\b'
            result = re.sub(pattern, substitute, result)

        self.logger.debug(f"ES|QL field substitutions: {substitutions}")
        return result

    def substitute_fields_lucene(
        self,
        query: str,
        available_fields: set[str],
        enabled: bool = True
    ) -> str:
        """
        Substitute ECS field names in a Lucene query.

        Lucene queries use field:value syntax, so we need to handle patterns like:
        - field.name:value
        - field.name:"quoted value"
        - field.name:(value1 OR value2)

        Args:
            query: Original Lucene query
            available_fields: Set of fields available in target index
            enabled: If False, return query unchanged

        Returns:
            Query with substituted field names
        """
        if not enabled or not available_fields:
            return query

        substitutions = {}

        # Find all ECS fields that need substitution
        for ecs_field in self.FIELD_ALIASES.keys():
            # Look for field:value pattern
            pattern = rf'\b{re.escape(ecs_field)}:'
            if re.search(pattern, query):
                substitute = self.find_substitute(ecs_field, available_fields)
                if substitute:
                    substitutions[ecs_field] = substitute

        if not substitutions:
            return query

        # Apply substitutions
        result = query
        for ecs_field in sorted(substitutions.keys(), key=len, reverse=True):
            substitute = substitutions[ecs_field]
            # Replace field:value patterns
            pattern = rf'\b{re.escape(ecs_field)}:'
            replacement = f'{substitute}:'
            result = re.sub(pattern, replacement, result)

        self.logger.debug(f"Lucene field substitutions: {substitutions}")
        return result

    def substitute_fields_eql(
        self,
        query: str,
        available_fields: set[str],
        enabled: bool = True
    ) -> str:
        """
        Substitute ECS field names in an EQL query.

        EQL queries use field names in expressions like:
        - process where process.name == "cmd.exe"
        - file.path like "*.exe"

        Args:
            query: Original EQL query
            available_fields: Set of fields available in target index
            enabled: If False, return query unchanged

        Returns:
            Query with substituted field names
        """
        if not enabled or not available_fields:
            return query

        substitutions = {}

        # Find all ECS fields that need substitution
        for ecs_field in self.FIELD_ALIASES.keys():
            if ecs_field in query:
                substitute = self.find_substitute(ecs_field, available_fields)
                if substitute:
                    substitutions[ecs_field] = substitute

        if not substitutions:
            return query

        # Apply substitutions (longest field names first)
        result = query
        for ecs_field in sorted(substitutions.keys(), key=len, reverse=True):
            substitute = substitutions[ecs_field]
            # Use word boundaries
            pattern = rf'\b{re.escape(ecs_field)}\b'
            result = re.sub(pattern, substitute, result)

        self.logger.debug(f"EQL field substitutions: {substitutions}")
        return result

    def get_substitution_report(
        self,
        query: str,
        available_fields: set[str]
    ) -> dict[str, Any]:
        """
        Generate a report of field substitutions that would be applied.

        Useful for debugging and transparency.

        Args:
            query: Query to analyse
            available_fields: Set of fields available in target index

        Returns:
            Report with original fields, substitutes, and unresolved fields
        """
        substitutions = {}
        unresolved = []

        for ecs_field in self.FIELD_ALIASES.keys():
            if ecs_field in query:
                substitute = self.find_substitute(ecs_field, available_fields)
                if substitute:
                    substitutions[ecs_field] = substitute
                elif ecs_field not in available_fields:
                    unresolved.append(ecs_field)

        return {
            "substitutions": substitutions,
            "unresolved_fields": unresolved,
            "substitution_count": len(substitutions),
            "unresolved_count": len(unresolved)
        }

    def clear_cache(self) -> None:
        """Clear the field mapping cache."""
        self._field_cache.clear()
