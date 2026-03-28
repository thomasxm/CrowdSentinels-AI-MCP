"""Tests for FieldMapper - field name substitution for different log schemas."""

from unittest.mock import MagicMock


class TestFieldMapper:
    """Test the FieldMapper class for field name substitution."""

    def test_substitute_fields_esql_simple(self):
        """Test ES|QL field substitution with simple field names."""
        from src.clients.common.field_mapper import FieldMapper

        mapper = FieldMapper()

        # Simulate winlogbeat field mappings
        available_fields = {
            "winlog.event_data.Image",
            "winlog.event_data.CommandLine",
            "winlog.event_data.User",
            "host.hostname",
            "event.code",
            "@timestamp",
        }

        query = """FROM logs-*
| WHERE process.name == "powershell.exe"
| KEEP process.name, process.command_line, user.name"""

        result = mapper.substitute_fields_esql(query, available_fields)

        # Should substitute ECS fields with winlogbeat fields
        assert "winlog.event_data.Image" in result
        assert "winlog.event_data.CommandLine" in result
        assert "winlog.event_data.User" in result
        assert "process.name" not in result  # Should be replaced

    def test_substitute_fields_esql_no_substitution_needed(self):
        """Test that no substitution happens when fields already match."""
        from src.clients.common.field_mapper import FieldMapper

        mapper = FieldMapper()

        # Fields already exist in index
        available_fields = {"process.name", "process.command_line", "user.name", "@timestamp"}

        query = '''FROM logs-* | WHERE process.name == "cmd.exe"'''

        result = mapper.substitute_fields_esql(query, available_fields)

        # Should remain unchanged
        assert result == query

    def test_substitute_fields_lucene(self):
        """Test Lucene query field substitution."""
        from src.clients.common.field_mapper import FieldMapper

        mapper = FieldMapper()

        available_fields = {"winlog.event_data.Image", "winlog.event_data.CommandLine", "event.code"}

        query = "process.name:powershell.exe AND process.command_line:*enc*"

        result = mapper.substitute_fields_lucene(query, available_fields)

        assert "winlog.event_data.Image:powershell.exe" in result
        assert "winlog.event_data.CommandLine:*enc*" in result

    def test_substitute_fields_eql(self):
        """Test EQL query field substitution."""
        from src.clients.common.field_mapper import FieldMapper

        mapper = FieldMapper()

        available_fields = {"winlog.event_data.Image", "winlog.event_data.CommandLine", "winlog.event_data.ParentImage"}

        query = '''process where process.name == "powershell.exe" and
                   process.parent.name == "cmd.exe"'''

        result = mapper.substitute_fields_eql(query, available_fields)

        assert "winlog.event_data.Image" in result
        assert "winlog.event_data.ParentImage" in result

    def test_get_field_mappings_from_index(self):
        """Test extracting field mappings from an index."""
        from src.clients.common.field_mapper import FieldMapper

        # Mock Elasticsearch client
        mock_client = MagicMock()
        mock_client.indices.get_mapping.return_value = {
            "winlogbeat-2024.01.01": {
                "mappings": {
                    "properties": {
                        "winlog": {
                            "properties": {
                                "event_data": {
                                    "properties": {
                                        "Image": {"type": "keyword"},
                                        "CommandLine": {"type": "text"},
                                        "User": {"type": "keyword"},
                                    }
                                }
                            }
                        },
                        "event": {"properties": {"code": {"type": "keyword"}}},
                        "host": {"properties": {"hostname": {"type": "keyword"}}},
                    }
                }
            }
        }

        mapper = FieldMapper(client=mock_client)
        fields = mapper.get_index_fields("winlogbeat-*")

        assert "winlog.event_data.Image" in fields
        assert "winlog.event_data.CommandLine" in fields
        assert "event.code" in fields
        assert "host.hostname" in fields

    def test_field_aliases_mapping(self):
        """Test that field aliases are correctly defined."""
        from src.clients.common.field_mapper import FieldMapper

        mapper = FieldMapper()

        # Check key aliases exist
        assert "process.name" in mapper.FIELD_ALIASES
        assert "process.command_line" in mapper.FIELD_ALIASES
        assert "process.parent.name" in mapper.FIELD_ALIASES
        assert "user.name" in mapper.FIELD_ALIASES
        assert "host.name" in mapper.FIELD_ALIASES
        assert "source.ip" in mapper.FIELD_ALIASES
        assert "destination.ip" in mapper.FIELD_ALIASES

    def test_substitute_preserves_operators(self):
        """Test that substitution preserves query operators and structure."""
        from src.clients.common.field_mapper import FieldMapper

        mapper = FieldMapper()

        available_fields = {"winlog.event_data.Image", "event.code"}

        # ES|QL with complex operators
        query = """FROM logs-*
| WHERE process.name LIKE "power*" AND NOT process.name == "notepad.exe"
| STATS count = COUNT(*) BY process.name"""

        result = mapper.substitute_fields_esql(query, available_fields)

        assert "LIKE" in result
        assert "AND NOT" in result
        assert "STATS" in result
        assert "BY" in result

    def test_substitute_with_nested_fields(self):
        """Test substitution of deeply nested fields."""
        from src.clients.common.field_mapper import FieldMapper

        mapper = FieldMapper()

        available_fields = {"winlog.event_data.TargetFilename", "file.hash.sha256"}

        query = '''FROM logs-* | WHERE file.path == "/tmp/malware.exe"'''

        result = mapper.substitute_fields_esql(query, available_fields)

        # file.path should map to winlog.event_data.TargetFilename
        assert "winlog.event_data.TargetFilename" in result

    def test_caching_field_mappings(self):
        """Test that field mappings are cached for performance."""
        from src.clients.common.field_mapper import FieldMapper

        mock_client = MagicMock()
        mock_client.indices.get_mapping.return_value = {
            "test-index": {"mappings": {"properties": {"field1": {"type": "keyword"}}}}
        }

        mapper = FieldMapper(client=mock_client)

        # First call
        mapper.get_index_fields("test-index")
        # Second call (should use cache)
        mapper.get_index_fields("test-index")

        # get_mapping should only be called once
        assert mock_client.indices.get_mapping.call_count == 1

    def test_disabled_substitution(self):
        """Test that substitution can be disabled."""
        from src.clients.common.field_mapper import FieldMapper

        mapper = FieldMapper()

        available_fields = {"winlog.event_data.Image"}
        query = '''FROM logs-* | WHERE process.name == "cmd.exe"'''

        # With substitution disabled
        result = mapper.substitute_fields_esql(query, available_fields, enabled=False)

        # Should remain unchanged
        assert result == query


class TestFieldMapperIntegration:
    """Integration tests for FieldMapper with other components."""

    def test_esql_client_uses_field_mapper(self):
        """Test that ESQLClient integrates with FieldMapper."""
        # This will be tested after implementation

    def test_eql_client_uses_field_mapper(self):
        """Test that EQLQueryClient integrates with FieldMapper."""
        # This will be tested after implementation

    def test_lucene_search_uses_field_mapper(self):
        """Test that search_with_lucene integrates with FieldMapper."""
        # This will be tested after implementation
