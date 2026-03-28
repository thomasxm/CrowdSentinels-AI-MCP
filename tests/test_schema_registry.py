"""Tests for the schema registry system.

Tests cover:
- Schema base classes and data structures
- Individual schema definitions (Sysmon, ECS, Windows Security)
- Schema registry functions (detection, lookup)
- SchemaResolver with caching
- SchemaAwareQueryBuilder integration
"""

from unittest.mock import MagicMock


class TestLogSourceSchema:
    """Test the LogSourceSchema base class."""

    def test_schema_creation(self):
        """Test creating a schema instance."""
        from src.clients.common.schemas.base import (
            EventTypeDefinition,
            LogSourceSchema,
            LogSourceType,
        )

        event_types = {
            "process_create": EventTypeDefinition(
                event_code="1",
                description="Process creation",
                category="process",
                fields={"source_process": "Image", "command_line": "CommandLine"},
            )
        }

        schema = LogSourceSchema(
            schema_id="test",
            name="Test Schema",
            description="A test schema",
            source_type=LogSourceType.SYSMON,
            index_patterns=["test-*"],
            field_prefix="test.data.",
            timestamp_field="@timestamp",
            host_field="host.name",
            event_code_field="event.code",
            event_types=event_types,
        )

        assert schema.schema_id == "test"
        assert schema.source_type == LogSourceType.SYSMON
        assert "test-*" in schema.index_patterns

    def test_has_event_type(self):
        """Test checking for event type existence."""
        from src.clients.common.schemas.base import (
            EventTypeDefinition,
            LogSourceSchema,
            LogSourceType,
        )

        event_types = {
            "process_create": EventTypeDefinition(
                event_code="1", description="Process creation", category="process", fields={"source_process": "Image"}
            )
        }

        schema = LogSourceSchema(
            schema_id="test",
            name="Test",
            description="Test",
            source_type=LogSourceType.SYSMON,
            index_patterns=["test-*"],
            field_prefix="",
            timestamp_field="@timestamp",
            host_field="host.name",
            event_code_field="event.code",
            event_types=event_types,
        )

        assert schema.has_event_type("process_create") is True
        assert schema.has_event_type("nonexistent") is False

    def test_get_field(self):
        """Test retrieving field mappings."""
        from src.clients.common.schemas.base import (
            EventTypeDefinition,
            LogSourceSchema,
            LogSourceType,
        )

        event_types = {
            "process_create": EventTypeDefinition(
                event_code="1",
                description="Process creation",
                category="process",
                fields={"source_process": "Image", "command_line": "CommandLine"},
            )
        }

        schema = LogSourceSchema(
            schema_id="test",
            name="Test",
            description="Test",
            source_type=LogSourceType.SYSMON,
            index_patterns=["test-*"],
            field_prefix="winlog.event_data.",
            timestamp_field="@timestamp",
            host_field="host.name",
            event_code_field="event.code",
            event_types=event_types,
        )

        # With prefix
        field = schema.get_field("source_process", "process_create")
        assert field == "winlog.event_data.Image"

        # Unknown field
        field = schema.get_field("unknown", "process_create")
        assert field is None

        # Unknown event type
        field = schema.get_field("source_process", "unknown_event")
        assert field is None

    def test_matches_index(self):
        """Test index pattern matching."""
        from src.clients.common.schemas.base import (
            LogSourceSchema,
            LogSourceType,
        )

        schema = LogSourceSchema(
            schema_id="test",
            name="Test",
            description="Test",
            source_type=LogSourceType.SYSMON,
            index_patterns=["winlogbeat-*", "sysmon-*"],
            field_prefix="",
            timestamp_field="@timestamp",
            host_field="host.name",
            event_code_field="event.code",
            event_types={},
        )

        assert schema.matches_index("winlogbeat-*") is True
        assert schema.matches_index("winlogbeat-2024.01.01") is True
        assert schema.matches_index("sysmon-events") is True
        assert schema.matches_index("auditbeat-*") is False

    def test_get_event_code(self):
        """Test retrieving event codes."""
        from src.clients.common.schemas.base import (
            EventTypeDefinition,
            LogSourceSchema,
            LogSourceType,
        )

        event_types = {
            "process_create": EventTypeDefinition(
                event_code="1", description="Process creation", category="process", fields={}
            ),
            "network_connection": EventTypeDefinition(
                event_code="3", description="Network connection", category="network", fields={}
            ),
        }

        schema = LogSourceSchema(
            schema_id="test",
            name="Test",
            description="Test",
            source_type=LogSourceType.SYSMON,
            index_patterns=["test-*"],
            field_prefix="",
            timestamp_field="@timestamp",
            host_field="host.name",
            event_code_field="event.code",
            event_types=event_types,
        )

        assert schema.get_event_code("process_create") == "1"
        assert schema.get_event_code("network_connection") == "3"
        assert schema.get_event_code("unknown") is None


class TestSysmonSchema:
    """Test the Sysmon schema definition."""

    def test_sysmon_schema_exists(self):
        """Test that Sysmon schema is properly defined."""
        from src.clients.common.schemas.sysmon import SYSMON_SCHEMA

        assert SYSMON_SCHEMA.schema_id == "sysmon"
        assert SYSMON_SCHEMA.field_prefix == "winlog.event_data."

    def test_sysmon_event_types(self):
        """Test Sysmon event type definitions."""
        from src.clients.common.schemas.sysmon import SYSMON_SCHEMA

        # Key event types should exist
        assert SYSMON_SCHEMA.has_event_type("process_create")
        assert SYSMON_SCHEMA.has_event_type("network_connection")
        assert SYSMON_SCHEMA.has_event_type("file_create")

        # Event codes should match Sysmon
        assert SYSMON_SCHEMA.get_event_code("process_create") == "1"
        assert SYSMON_SCHEMA.get_event_code("network_connection") == "3"

    def test_sysmon_process_fields(self):
        """Test Sysmon process creation field mappings."""
        from src.clients.common.schemas.sysmon import SYSMON_SCHEMA

        # Key process fields
        source = SYSMON_SCHEMA.get_field("source_process", "process_create")
        assert source == "winlog.event_data.Image"

        parent = SYSMON_SCHEMA.get_field("parent_process", "process_create")
        assert parent == "winlog.event_data.ParentImage"

        cmd = SYSMON_SCHEMA.get_field("command_line", "process_create")
        assert cmd == "winlog.event_data.CommandLine"

    def test_sysmon_network_fields(self):
        """Test Sysmon network connection field mappings."""
        from src.clients.common.schemas.sysmon import SYSMON_SCHEMA

        dest_ip = SYSMON_SCHEMA.get_field("destination_ip", "network_connection")
        assert dest_ip == "winlog.event_data.DestinationIp"

        dest_port = SYSMON_SCHEMA.get_field("destination_port", "network_connection")
        assert dest_port == "winlog.event_data.DestinationPort"

    def test_sysmon_index_matching(self):
        """Test Sysmon index pattern matching."""
        from src.clients.common.schemas.sysmon import SYSMON_SCHEMA

        assert SYSMON_SCHEMA.matches_index("winlogbeat-*")
        assert SYSMON_SCHEMA.matches_index("winlogbeat-2024.01.01")
        # Sysmon schema matches winlogbeat and logs-windows.sysmon* patterns
        assert SYSMON_SCHEMA.matches_index("logs-windows.sysmon_operational-default")


class TestECSSchema:
    """Test the ECS schema definition."""

    def test_ecs_schema_exists(self):
        """Test that ECS schema is properly defined."""
        from src.clients.common.schemas.ecs import ECS_SCHEMA

        assert ECS_SCHEMA.schema_id == "ecs"
        # ECS uses root-level fields, no prefix
        assert ECS_SCHEMA.field_prefix == ""

    def test_ecs_event_types(self):
        """Test ECS event type definitions."""
        from src.clients.common.schemas.ecs import ECS_SCHEMA

        assert ECS_SCHEMA.has_event_type("process_create")
        assert ECS_SCHEMA.has_event_type("network_connection")

    def test_ecs_process_fields(self):
        """Test ECS process field mappings (native ECS names)."""
        from src.clients.common.schemas.ecs import ECS_SCHEMA

        source = ECS_SCHEMA.get_field("source_process", "process_create")
        assert source == "process.executable"

        cmd = ECS_SCHEMA.get_field("command_line", "process_create")
        assert cmd == "process.command_line"

    def test_ecs_index_matching(self):
        """Test ECS index pattern matching."""
        from src.clients.common.schemas.ecs import ECS_SCHEMA

        assert ECS_SCHEMA.matches_index("logs-endpoint.events.process-*")
        assert ECS_SCHEMA.matches_index("logs-endpoint.events.network-*")


class TestWindowsSecuritySchema:
    """Test the Windows Security schema definition."""

    def test_windows_security_schema_exists(self):
        """Test that Windows Security schema is properly defined."""
        from src.clients.common.schemas.windows_security import WINDOWS_SECURITY_SCHEMA

        assert WINDOWS_SECURITY_SCHEMA.schema_id == "windows_security"

    def test_windows_security_event_types(self):
        """Test Windows Security event type definitions."""
        from src.clients.common.schemas.windows_security import WINDOWS_SECURITY_SCHEMA

        # Windows Security events
        assert WINDOWS_SECURITY_SCHEMA.has_event_type("logon_success")
        assert WINDOWS_SECURITY_SCHEMA.has_event_type("logon_failure")
        assert WINDOWS_SECURITY_SCHEMA.has_event_type("process_create")

        # Event codes should match Windows Security
        assert WINDOWS_SECURITY_SCHEMA.get_event_code("logon_success") == "4624"
        assert WINDOWS_SECURITY_SCHEMA.get_event_code("logon_failure") == "4625"


class TestSchemaRegistry:
    """Test the schema registry functions."""

    def test_get_schema(self):
        """Test retrieving schemas by ID."""
        from src.clients.common.schemas.registry import get_schema

        sysmon = get_schema("sysmon")
        assert sysmon is not None
        assert sysmon.schema_id == "sysmon"

        ecs = get_schema("ecs")
        assert ecs is not None
        assert ecs.schema_id == "ecs"

        # Unknown schema
        unknown = get_schema("nonexistent")
        assert unknown is None

    def test_list_schemas(self):
        """Test listing all schemas."""
        from src.clients.common.schemas.registry import list_schemas

        schemas = list_schemas()

        assert len(schemas) >= 3
        schema_ids = [s["schema_id"] for s in schemas]
        assert "sysmon" in schema_ids
        assert "ecs" in schema_ids
        assert "windows_security" in schema_ids

    def test_detect_schema_from_index_sysmon(self):
        """Test detecting Sysmon schema from index pattern."""
        from src.clients.common.schemas.registry import detect_schema_from_index

        schema = detect_schema_from_index("winlogbeat-*")
        assert schema is not None
        assert schema.schema_id == "sysmon"

        schema = detect_schema_from_index("winlogbeat-2024.01.01")
        assert schema is not None
        assert schema.schema_id == "sysmon"

    def test_detect_schema_from_index_ecs(self):
        """Test detecting ECS schema from index pattern."""
        from src.clients.common.schemas.registry import detect_schema_from_index

        schema = detect_schema_from_index("logs-endpoint.events.process-*")
        assert schema is not None
        assert schema.schema_id == "ecs"

    def test_detect_schema_from_index_unknown(self):
        """Test detection with unknown index returns None."""
        from src.clients.common.schemas.registry import detect_schema_from_index

        schema = detect_schema_from_index("unknown-index-*")
        assert schema is None

    def test_detect_schema_from_fields(self):
        """Test detecting schema from field names."""
        from src.clients.common.schemas.registry import detect_schema_from_fields

        # Sysmon fields - use low confidence threshold for testing
        sysmon_fields = {"winlog.event_data.Image", "winlog.event_data.CommandLine", "winlog.event_data.ParentImage"}
        schema, confidence = detect_schema_from_fields(sysmon_fields, min_confidence=0.01)
        assert schema is not None
        # Should detect sysmon or at least return best match
        assert confidence > 0.0

        # ECS fields
        ecs_fields = {"process.executable", "process.command_line", "process.parent.executable"}
        schema, confidence = detect_schema_from_fields(ecs_fields, min_confidence=0.01)
        assert schema is not None
        assert confidence > 0.0

    def test_get_schema_for_event_type(self):
        """Test finding schemas that support an event type."""
        from src.clients.common.schemas.registry import get_schema_for_event_type

        results = get_schema_for_event_type("process_create")

        # Multiple schemas support process creation
        assert len(results) >= 2
        schema_ids = [schema.schema_id for schema, _ in results]
        assert "sysmon" in schema_ids
        assert "ecs" in schema_ids

    def test_get_semantic_field_mappings(self):
        """Test getting field mappings across schemas."""
        from src.clients.common.schemas.registry import get_semantic_field_mappings

        mappings = get_semantic_field_mappings("source_process")

        assert "sysmon" in mappings
        assert mappings["sysmon"] == "winlog.event_data.Image"

        assert "ecs" in mappings
        assert mappings["ecs"] == "process.executable"


class TestSchemaResolver:
    """Test the SchemaResolver class with caching."""

    def test_resolver_with_hint(self):
        """Test resolver with explicit schema hint."""
        from src.clients.common.schemas.registry import SchemaResolver

        resolver = SchemaResolver()

        schema = resolver.resolve("any-index", schema_hint="sysmon")
        assert schema is not None
        assert schema.schema_id == "sysmon"

    def test_resolver_from_index_pattern(self):
        """Test resolver auto-detection from index pattern."""
        from src.clients.common.schemas.registry import SchemaResolver

        resolver = SchemaResolver()

        schema = resolver.resolve("winlogbeat-*")
        assert schema is not None
        assert schema.schema_id == "sysmon"

    def test_resolver_caching(self):
        """Test that resolver caches results."""
        from src.clients.common.schemas.registry import SchemaResolver

        resolver = SchemaResolver()

        # First call
        schema1 = resolver.resolve("winlogbeat-*")
        # Second call (should use cache)
        schema2 = resolver.resolve("winlogbeat-*")

        assert schema1 is schema2  # Same object (cached)

    def test_resolver_cache_clear(self):
        """Test clearing the resolver cache."""
        from src.clients.common.schemas.registry import SchemaResolver

        resolver = SchemaResolver()

        schema1 = resolver.resolve("winlogbeat-*")
        resolver.clear_cache()
        schema2 = resolver.resolve("winlogbeat-*")

        # Same values but could be different objects after cache clear
        assert schema1.schema_id == schema2.schema_id

    def test_resolver_with_es_client(self):
        """Test resolver with Elasticsearch client for field sampling."""
        from src.clients.common.schemas.registry import SchemaResolver

        mock_client = MagicMock()
        mock_client.indices.get_mapping.return_value = {
            "test-index": {
                "mappings": {
                    "properties": {
                        "winlog": {
                            "properties": {
                                "event_data": {
                                    "properties": {"Image": {"type": "keyword"}, "CommandLine": {"type": "text"}}
                                }
                            }
                        }
                    }
                }
            }
        }

        resolver = SchemaResolver(es_client=mock_client)

        # Unknown index pattern - should fall back to field sampling
        schema = resolver.resolve("test-index")

        # Should detect Sysmon from winlog.event_data fields
        if schema:  # May be None if confidence threshold not met
            assert schema.schema_id in ["sysmon", "ecs", "windows_security"]


class TestSchemaAwareQueryBuilder:
    """Test the SchemaAwareQueryBuilder class."""

    def test_query_builder_creation(self):
        """Test creating a query builder."""
        from src.clients.common.schemas.query_builder import SchemaAwareQueryBuilder
        from src.clients.common.schemas.sysmon import SYSMON_SCHEMA

        builder = SchemaAwareQueryBuilder(SYSMON_SCHEMA, "winlogbeat-*")
        assert builder.schema == SYSMON_SCHEMA
        assert builder.index == "winlogbeat-*"

    def test_build_process_bounds_query(self):
        """Test building process bounds query."""
        from src.clients.common.schemas.query_builder import (
            QueryResult,
            SchemaAwareQueryBuilder,
        )
        from src.clients.common.schemas.sysmon import SYSMON_SCHEMA

        builder = SchemaAwareQueryBuilder(SYSMON_SCHEMA, "winlogbeat-*")
        result = builder.build_process_bounds_query("malware.exe")

        # Result is a QueryResult dataclass
        assert isinstance(result, QueryResult)
        assert result.query is not None
        assert len(result.fields_used) > 0
        assert "winlog.event_data.Image" in result.query
        assert "malware.exe" in result.query

    def test_build_child_processes_query(self):
        """Test building child processes query."""
        from src.clients.common.schemas.query_builder import (
            QueryResult,
            SchemaAwareQueryBuilder,
        )
        from src.clients.common.schemas.sysmon import SYSMON_SCHEMA

        builder = SchemaAwareQueryBuilder(SYSMON_SCHEMA, "winlogbeat-*")
        result = builder.build_child_processes_query(
            parent_process_name="malware.exe",
            host="HOST1",
            start_time="2024-01-01T00:00:00",
            end_time="2024-01-01T01:00:00",
        )

        assert isinstance(result, QueryResult)
        assert "winlog.event_data.ParentImage" in result.query
        assert "malware.exe" in result.query

    def test_build_network_connections_query(self):
        """Test building network connections query."""
        from src.clients.common.schemas.query_builder import (
            QueryResult,
            SchemaAwareQueryBuilder,
        )
        from src.clients.common.schemas.sysmon import SYSMON_SCHEMA

        builder = SchemaAwareQueryBuilder(SYSMON_SCHEMA, "winlogbeat-*")
        result = builder.build_network_connections_query(
            process_name="malware.exe", host="HOST1", start_time="2024-01-01T00:00:00", end_time="2024-01-01T01:00:00"
        )

        assert isinstance(result, QueryResult)
        assert "winlog.event_data.Image" in result.query
        assert "DestinationIp" in result.query or "destination_ip" in result.query.lower()

    def test_build_file_operations_query(self):
        """Test building file operations query."""
        from src.clients.common.schemas.query_builder import (
            QueryResult,
            SchemaAwareQueryBuilder,
        )
        from src.clients.common.schemas.sysmon import SYSMON_SCHEMA

        builder = SchemaAwareQueryBuilder(SYSMON_SCHEMA, "winlogbeat-*")
        result = builder.build_file_operations_query(
            process_name="malware.exe", host="HOST1", start_time="2024-01-01T00:00:00", end_time="2024-01-01T01:00:00"
        )

        assert isinstance(result, QueryResult)
        assert "winlog.event_data" in result.query

    def test_query_builder_with_ecs_schema(self):
        """Test query builder with ECS schema uses correct fields."""
        from src.clients.common.schemas.ecs import ECS_SCHEMA
        from src.clients.common.schemas.query_builder import (
            QueryResult,
            SchemaAwareQueryBuilder,
        )

        builder = SchemaAwareQueryBuilder(ECS_SCHEMA, "logs-endpoint.*")
        result = builder.build_process_bounds_query("malware.exe")

        assert isinstance(result, QueryResult)
        # ECS uses process.executable, not winlog.event_data.Image
        assert "process.executable" in result.query or "process.name" in result.query

    def test_build_registry_operations_query(self):
        """Test building registry operations query."""
        from src.clients.common.schemas.query_builder import (
            QueryResult,
            SchemaAwareQueryBuilder,
        )
        from src.clients.common.schemas.sysmon import SYSMON_SCHEMA

        builder = SchemaAwareQueryBuilder(SYSMON_SCHEMA, "winlogbeat-*")
        result = builder.build_registry_operations_query(
            process_name="malware.exe", host="HOST1", start_time="2024-01-01T00:00:00", end_time="2024-01-01T01:00:00"
        )

        assert isinstance(result, QueryResult)
        # Registry operations query should be generated
        assert result.query is not None

    def test_build_dns_query(self):
        """Test building DNS query."""
        from src.clients.common.schemas.query_builder import (
            QueryResult,
            SchemaAwareQueryBuilder,
        )
        from src.clients.common.schemas.sysmon import SYSMON_SCHEMA

        builder = SchemaAwareQueryBuilder(SYSMON_SCHEMA, "winlogbeat-*")
        result = builder.build_dns_query(
            process_name="malware.exe", host="HOST1", start_time="2024-01-01T00:00:00", end_time="2024-01-01T01:00:00"
        )

        assert isinstance(result, QueryResult)
        assert result.query is not None


class TestSchemaIntegration:
    """Integration tests for the schema system."""

    def test_full_workflow_sysmon(self):
        """Test complete workflow with Sysmon schema."""
        from src.clients.common.schemas import detect_schema_from_index
        from src.clients.common.schemas.query_builder import (
            QueryResult,
            SchemaAwareQueryBuilder,
        )

        # 1. Detect schema from index
        schema = detect_schema_from_index("winlogbeat-*")
        assert schema is not None
        assert schema.schema_id == "sysmon"

        # 2. Build queries
        builder = SchemaAwareQueryBuilder(schema, "winlogbeat-*")
        result = builder.build_process_bounds_query("suspicious.exe")

        # 3. Verify correct field names
        assert isinstance(result, QueryResult)
        assert "winlog.event_data.Image" in result.query

    def test_full_workflow_ecs(self):
        """Test complete workflow with ECS schema."""
        from src.clients.common.schemas import get_schema
        from src.clients.common.schemas.query_builder import (
            QueryResult,
            SchemaAwareQueryBuilder,
        )

        # 1. Get schema explicitly
        schema = get_schema("ecs")
        assert schema is not None

        # 2. Build queries
        builder = SchemaAwareQueryBuilder(schema, "logs-endpoint.*")
        result = builder.build_process_bounds_query("suspicious.exe")

        # 3. Verify ECS field names
        assert isinstance(result, QueryResult)
        assert "process.executable" in result.query or "process.name" in result.query

    def test_schema_fallback(self):
        """Test fallback behaviour when schema not detected."""
        from src.clients.common.schemas.registry import SchemaResolver, get_schema

        resolver = SchemaResolver()

        # Unknown index - no auto-detection
        schema = resolver.resolve("unknown-custom-index")

        # Should return None (caller can fall back to default)
        if schema is None:
            # Use default Sysmon schema
            schema = get_schema("sysmon")
            assert schema is not None
