"""Base classes for log source schema definitions.

This module provides the core dataclasses used to define log source schemas,
enabling adaptive field mapping across different log formats.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Any
import json


class LogSourceType(Enum):
    """Enumeration of supported log source types."""
    SYSMON = "sysmon"
    WINDOWS_SECURITY = "windows_security"
    ECS = "ecs"
    CEF = "cef"
    AUDITBEAT = "auditbeat"
    CUSTOM = "custom"


@dataclass
class EventTypeDefinition:
    """Defines field mappings for a specific event type.

    Each event type (e.g., process creation, network connection) has its own
    set of fields that may be named differently across log sources.

    Attributes:
        event_code: The event ID or action code (e.g., "1" for Sysmon, "4688" for Security)
        description: Human-readable description of the event type
        fields: Mapping of semantic field names to actual field names
            Example: {"source_process": "Image", "command_line": "CommandLine"}
        category: Optional event category for grouping
    """
    event_code: str
    description: str
    fields: Dict[str, str]
    category: Optional[str] = None

    def get_field(self, semantic_name: str) -> Optional[str]:
        """Get the actual field name for a semantic concept.

        Args:
            semantic_name: The semantic field name (e.g., "source_process")

        Returns:
            The actual field name (e.g., "Image") or None if not defined
        """
        return self.fields.get(semantic_name)

    def has_field(self, semantic_name: str) -> bool:
        """Check if this event type defines a semantic field."""
        return semantic_name in self.fields

    def list_semantic_fields(self) -> List[str]:
        """List all semantic field names defined for this event type."""
        return list(self.fields.keys())

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialisation."""
        return {
            "event_code": self.event_code,
            "description": self.description,
            "fields": self.fields,
            "category": self.category,
        }


@dataclass
class LogSourceSchema:
    """Complete schema for a log source type.

    A schema defines how to map semantic field concepts to actual field names
    in a specific log source. This enables queries to be written using semantic
    names and then translated to the correct field names for the target index.

    Attributes:
        name: Human-readable name of the schema
        schema_id: Unique identifier for the schema (e.g., "sysmon", "ecs")
        source_type: The type of log source
        description: Detailed description of the schema
        index_patterns: List of index patterns that typically use this schema
        field_prefix: Prefix applied to all field names (e.g., "winlog.event_data.")
        event_types: Mapping of event type names to their definitions
        common_fields: Fields that are common across all event types
        timestamp_field: The field used for timestamps (default: "@timestamp")
        host_field: The field containing hostname (default: "host.name")
        event_code_field: The field containing event codes (default: "event.code")
    """
    name: str
    schema_id: str
    source_type: LogSourceType
    description: str
    index_patterns: List[str]
    field_prefix: str
    event_types: Dict[str, EventTypeDefinition]
    common_fields: Dict[str, str] = field(default_factory=dict)
    timestamp_field: str = "@timestamp"
    host_field: str = "host.name"
    event_code_field: str = "event.code"
    event_code_alternatives: List[str] = field(default_factory=list)

    def get_field(
        self,
        semantic_name: str,
        event_type: Optional[str] = None
    ) -> Optional[str]:
        """Get the actual field name for a semantic concept.

        Args:
            semantic_name: The semantic field name (e.g., "source_process")
            event_type: Optional event type context (e.g., "process_access")

        Returns:
            Full field path (e.g., "winlog.event_data.SourceImage") or None
        """
        # Check event-specific fields first
        if event_type and event_type in self.event_types:
            event_def = self.event_types[event_type]
            if semantic_name in event_def.fields:
                field_name = event_def.fields[semantic_name]
                return f"{self.field_prefix}{field_name}"

        # Fall back to common fields
        if semantic_name in self.common_fields:
            field_name = self.common_fields[semantic_name]
            # Common fields may already include prefix or be at root level
            if field_name.startswith(self.field_prefix) or "." in field_name:
                return field_name
            return f"{self.field_prefix}{field_name}"

        # Check well-known fields
        if semantic_name == "timestamp":
            return self.timestamp_field
        if semantic_name == "hostname":
            return self.host_field
        if semantic_name == "event_code":
            return self.event_code_field

        return None

    def get_event_code(self, event_type: str) -> Optional[str]:
        """Get the event code for a specific event type.

        Args:
            event_type: The event type name (e.g., "process_create")

        Returns:
            The event code (e.g., "1") or None if not defined
        """
        if event_type in self.event_types:
            return self.event_types[event_type].event_code
        return None

    def get_event_code_fields(self) -> List[str]:
        """Get all possible event code field names (primary + alternatives).

        Returns:
            List of field names to try, in priority order.
            First is the primary field, followed by alternatives.

        Example:
            ["event.code", "winlog.event_id", "EventCode"]
        """
        fields = [self.event_code_field]
        for alt in self.event_code_alternatives:
            if alt not in fields:
                fields.append(alt)
        return fields

    def has_event_type(self, event_type: str) -> bool:
        """Check if this schema defines an event type."""
        return event_type in self.event_types

    def list_event_types(self) -> List[str]:
        """List all event types defined in this schema."""
        return list(self.event_types.keys())

    def get_all_fields(self, event_type: Optional[str] = None) -> Set[str]:
        """Get all actual field names for this schema.

        Args:
            event_type: Optional event type to limit fields

        Returns:
            Set of full field paths
        """
        fields = set()

        # Add common fields
        for field_name in self.common_fields.values():
            if field_name.startswith(self.field_prefix) or "." in field_name:
                fields.add(field_name)
            else:
                fields.add(f"{self.field_prefix}{field_name}")

        # Add event-specific fields
        if event_type:
            if event_type in self.event_types:
                for field_name in self.event_types[event_type].fields.values():
                    fields.add(f"{self.field_prefix}{field_name}")
        else:
            for event_def in self.event_types.values():
                for field_name in event_def.fields.values():
                    fields.add(f"{self.field_prefix}{field_name}")

        # Add well-known fields
        fields.add(self.timestamp_field)
        fields.add(self.host_field)
        fields.add(self.event_code_field)

        return fields

    def matches_index(self, index_pattern: str) -> bool:
        """Check if an index pattern matches this schema.

        Args:
            index_pattern: The index pattern to check

        Returns:
            True if the pattern matches any of this schema's patterns
        """
        import fnmatch

        for pattern in self.index_patterns:
            # Check both directions for wildcard matching
            if fnmatch.fnmatch(index_pattern, pattern):
                return True
            if fnmatch.fnmatch(pattern, index_pattern):
                return True
            # Also check for prefix matching
            pattern_base = pattern.rstrip("*")
            index_base = index_pattern.rstrip("*")
            if pattern_base and index_base:
                if index_base.startswith(pattern_base) or pattern_base.startswith(index_base):
                    return True

        return False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialisation."""
        return {
            "name": self.name,
            "schema_id": self.schema_id,
            "source_type": self.source_type.value,
            "description": self.description,
            "index_patterns": self.index_patterns,
            "field_prefix": self.field_prefix,
            "event_types": {
                name: event_def.to_dict()
                for name, event_def in self.event_types.items()
            },
            "common_fields": self.common_fields,
            "timestamp_field": self.timestamp_field,
            "host_field": self.host_field,
            "event_code_field": self.event_code_field,
            "event_code_alternatives": self.event_code_alternatives,
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LogSourceSchema":
        """Create a schema from a dictionary.

        Args:
            data: Dictionary containing schema data

        Returns:
            LogSourceSchema instance
        """
        event_types = {}
        for name, event_data in data.get("event_types", {}).items():
            event_types[name] = EventTypeDefinition(
                event_code=event_data["event_code"],
                description=event_data["description"],
                fields=event_data["fields"],
                category=event_data.get("category"),
            )

        return cls(
            name=data["name"],
            schema_id=data["schema_id"],
            source_type=LogSourceType(data["source_type"]),
            description=data["description"],
            index_patterns=data["index_patterns"],
            field_prefix=data["field_prefix"],
            event_types=event_types,
            common_fields=data.get("common_fields", {}),
            timestamp_field=data.get("timestamp_field", "@timestamp"),
            host_field=data.get("host_field", "host.name"),
            event_code_field=data.get("event_code_field", "event.code"),
            event_code_alternatives=data.get("event_code_alternatives", []),
        )
