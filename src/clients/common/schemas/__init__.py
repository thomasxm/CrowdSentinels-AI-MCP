"""Schema Registry for adaptive log source support.

This module provides schema definitions for different log sources (Sysmon, ECS,
Windows Security, etc.) enabling the hunt tools to adapt queries to different
field naming conventions.
"""

from .base import EventTypeDefinition, LogSourceSchema, LogSourceType
from .ecs import ECS_SCHEMA
from .registry import (
    SCHEMA_REGISTRY,
    detect_schema_from_fields,
    detect_schema_from_index,
    get_schema,
    list_schemas,
)
from .sysmon import SYSMON_SCHEMA
from .windows_security import WINDOWS_SECURITY_SCHEMA

__all__ = [
    # Base classes
    "LogSourceType",
    "EventTypeDefinition",
    "LogSourceSchema",
    # Registry functions
    "SCHEMA_REGISTRY",
    "get_schema",
    "detect_schema_from_index",
    "detect_schema_from_fields",
    "list_schemas",
    # Schema instances
    "SYSMON_SCHEMA",
    "ECS_SCHEMA",
    "WINDOWS_SECURITY_SCHEMA",
]
