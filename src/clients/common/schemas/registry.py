"""Schema registry with auto-detection capabilities.

This module provides the central registry for all log source schemas and
functions for detecting the appropriate schema based on index patterns
or field analysis.
"""

import logging
from typing import Any

from .base import LogSourceSchema
from .ecs import ECS_SCHEMA
from .sysmon import SYSMON_SCHEMA
from .windows_security import WINDOWS_SECURITY_SCHEMA

logger = logging.getLogger(__name__)


# Central schema registry
SCHEMA_REGISTRY: dict[str, LogSourceSchema] = {
    "sysmon": SYSMON_SCHEMA,
    "ecs": ECS_SCHEMA,
    "windows_security": WINDOWS_SECURITY_SCHEMA,
}


def get_schema(schema_id: str) -> LogSourceSchema | None:
    """Get a schema by its ID.

    Args:
        schema_id: The schema identifier (e.g., "sysmon", "ecs")

    Returns:
        The schema if found, None otherwise
    """
    return SCHEMA_REGISTRY.get(schema_id)


def list_schemas() -> list[dict[str, Any]]:
    """List all available schemas with summary information.

    Returns:
        List of schema summaries
    """
    return [
        {
            "schema_id": schema_id,
            "name": schema.name,
            "source_type": schema.source_type.value,
            "description": schema.description,
            "index_patterns": schema.index_patterns,
            "event_types": list(schema.event_types.keys()),
        }
        for schema_id, schema in SCHEMA_REGISTRY.items()
    ]


def detect_schema_from_index(index_pattern: str) -> LogSourceSchema | None:
    """Detect the appropriate schema based on index pattern.

    Checks the index pattern against known patterns for each schema.
    Returns the first matching schema.

    Args:
        index_pattern: The index pattern to match (e.g., "winlogbeat-*")

    Returns:
        The matching schema, or None if no match found
    """
    for schema in SCHEMA_REGISTRY.values():
        if schema.matches_index(index_pattern):
            logger.debug(f"Detected schema '{schema.schema_id}' for index '{index_pattern}'")
            return schema

    logger.debug(f"No schema detected for index '{index_pattern}'")
    return None


def detect_schema_from_fields(fields: set[str], min_confidence: float = 0.3) -> tuple[LogSourceSchema | None, float]:
    """Detect the appropriate schema by analysing available fields.

    Calculates a confidence score for each schema based on how many
    of its expected fields are present in the provided field set.

    Args:
        fields: Set of field names found in the index
        min_confidence: Minimum confidence score to return a match (0.0-1.0)

    Returns:
        Tuple of (schema, confidence) or (None, 0.0) if no match above threshold
    """
    best_schema: LogSourceSchema | None = None
    best_score: float = 0.0

    for schema_id, schema in SCHEMA_REGISTRY.items():
        score = _calculate_field_match_score(schema, fields)
        logger.debug(f"Schema '{schema_id}' field match score: {score:.2f}")

        if score > best_score:
            best_score = score
            best_schema = schema

    if best_score >= min_confidence:
        logger.info(f"Detected schema '{best_schema.schema_id}' with confidence {best_score:.2f}")
        return best_schema, best_score

    logger.debug(f"No schema matched with confidence >= {min_confidence}")
    return None, 0.0


def _calculate_field_match_score(schema: LogSourceSchema, available_fields: set[str]) -> float:
    """Calculate how well a set of fields matches a schema.

    Args:
        schema: The schema to match against
        available_fields: Set of available field names

    Returns:
        Match score between 0.0 and 1.0
    """
    # Get all expected fields from the schema
    expected_fields = schema.get_all_fields()

    if not expected_fields:
        return 0.0

    # Count matches (including partial matches for nested fields)
    matches = 0
    for expected in expected_fields:
        if expected in available_fields:
            matches += 1
        else:
            # Check for partial matches (e.g., winlog.event_data.* pattern)
            for available in available_fields:
                if available.startswith(expected) or expected.startswith(available):
                    matches += 0.5
                    break

    return matches / len(expected_fields)


def register_schema(schema: LogSourceSchema) -> None:
    """Register a new schema or update an existing one.

    Args:
        schema: The schema to register
    """
    SCHEMA_REGISTRY[schema.schema_id] = schema
    logger.info(f"Registered schema '{schema.schema_id}'")


def unregister_schema(schema_id: str) -> bool:
    """Remove a schema from the registry.

    Args:
        schema_id: The ID of the schema to remove

    Returns:
        True if the schema was removed, False if it didn't exist
    """
    if schema_id in SCHEMA_REGISTRY:
        del SCHEMA_REGISTRY[schema_id]
        logger.info(f"Unregistered schema '{schema_id}'")
        return True
    return False


def get_schema_for_event_type(event_type: str) -> list[tuple[LogSourceSchema, str]]:
    """Find all schemas that define a specific event type.

    Args:
        event_type: The event type to search for (e.g., "process_create")

    Returns:
        List of (schema, event_code) tuples for schemas that define this event type
    """
    results = []
    for schema in SCHEMA_REGISTRY.values():
        if schema.has_event_type(event_type):
            event_code = schema.get_event_code(event_type)
            results.append((schema, event_code))
    return results


def get_semantic_field_mappings(semantic_field: str) -> dict[str, str]:
    """Get the field name for a semantic concept across all schemas.

    Args:
        semantic_field: The semantic field name (e.g., "source_process")

    Returns:
        Dictionary mapping schema_id to actual field path
    """
    mappings = {}
    for schema_id, schema in SCHEMA_REGISTRY.items():
        # Try to find the field in any event type
        for event_type in schema.event_types:
            field = schema.get_field(semantic_field, event_type)
            if field:
                mappings[schema_id] = field
                break
    return mappings


class SchemaResolver:
    """Resolves schemas with caching and Elasticsearch integration.

    This class provides schema resolution with optional Elasticsearch client
    integration for field-based auto-detection.
    """

    def __init__(self, es_client: Any | None = None):
        """Initialise the schema resolver.

        Args:
            es_client: Optional Elasticsearch client for field sampling
        """
        self.es_client = es_client
        self._cache: dict[str, LogSourceSchema] = {}

    def resolve(self, index: str, schema_hint: str | None = None, use_cache: bool = True) -> LogSourceSchema | None:
        """Resolve the schema for an index.

        Resolution order:
        1. If schema_hint provided, use that schema directly
        2. Check cache for previously resolved schema
        3. Try to detect from index pattern
        4. If Elasticsearch client available, sample fields and detect

        Args:
            index: The index pattern
            schema_hint: Optional explicit schema ID
            use_cache: Whether to use cached results

        Returns:
            The resolved schema, or None if not found
        """
        # 1. Explicit schema hint
        if schema_hint:
            schema = get_schema(schema_hint)
            if schema:
                logger.debug(f"Using explicit schema hint: {schema_hint}")
                return schema
            logger.warning(f"Schema hint '{schema_hint}' not found in registry")

        # 2. Check cache
        if use_cache and index in self._cache:
            logger.debug(f"Using cached schema for index '{index}'")
            return self._cache[index]

        # 3. Detect from index pattern
        schema = detect_schema_from_index(index)
        if schema:
            self._cache[index] = schema
            return schema

        # 4. Sample fields from Elasticsearch
        if self.es_client:
            fields = self._sample_index_fields(index)
            if fields:
                schema, confidence = detect_schema_from_fields(fields)
                if schema:
                    logger.info(
                        f"Auto-detected schema '{schema.schema_id}' for '{index}' (confidence: {confidence:.2f})"
                    )
                    self._cache[index] = schema
                    return schema

        return None

    def _sample_index_fields(self, index: str, sample_size: int = 100) -> set[str]:
        """Sample fields from an Elasticsearch index.

        Args:
            index: The index to sample
            sample_size: Number of documents to sample

        Returns:
            Set of field names found in the sample
        """
        if not self.es_client:
            return set()

        try:
            # Get index mapping
            mapping = self.es_client.indices.get_mapping(index=index)

            fields = set()
            for idx_name, idx_mapping in mapping.items():
                self._extract_fields(idx_mapping.get("mappings", {}), "", fields)

            return fields

        except Exception as e:
            logger.warning(f"Failed to sample fields from '{index}': {e}")
            return set()

    def _extract_fields(self, obj: dict, prefix: str, fields: set[str]) -> None:
        """Recursively extract field names from mapping."""
        if "properties" in obj:
            for name, defn in obj["properties"].items():
                full_name = f"{prefix}{name}" if prefix else name
                fields.add(full_name)
                if isinstance(defn, dict):
                    self._extract_fields(defn, f"{full_name}.", fields)

    def clear_cache(self) -> None:
        """Clear the schema resolution cache."""
        self._cache.clear()
        logger.debug("Schema resolution cache cleared")
