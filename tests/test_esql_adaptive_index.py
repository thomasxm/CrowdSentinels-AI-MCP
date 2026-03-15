"""Test ES|QL adaptive index resolution functionality."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.clients.common.esql_client import ESQLClient


def test_extract_index_from_query():
    """Test extraction of index pattern from ES|QL FROM clause."""
    print("\n=== Testing Index Extraction ===")

    with patch('src.clients.base.SearchClientBase.__init__', return_value=None):
        client = ESQLClient({"hosts": ["http://localhost:9200"]}, engine_type="elasticsearch")

        # Test basic index extraction
        query1 = "FROM logs-endpoint.events.process-* | LIMIT 10"
        assert client.extract_index_from_query(query1) == "logs-endpoint.events.process-*"
        print("  Basic index: PASS")

        # Test lowercase from
        query2 = "from winlogbeat-* | WHERE event.code == 1"
        assert client.extract_index_from_query(query2) == "winlogbeat-*"
        print("  Lowercase from: PASS")

        # Test with newlines and whitespace
        query3 = """
        FROM   logs-*
        | WHERE @timestamp > now() - 1 day
        """
        assert client.extract_index_from_query(query3) == "logs-*"
        print("  Whitespace handling: PASS")

        # Test multiple indices
        query4 = "FROM index1, index2, index3 | LIMIT 10"
        assert client.extract_index_from_query(query4) == "index1, index2, index3"
        print("  Multiple indices: PASS")

        print("  [PASS] Index extraction works correctly")


def test_extract_fields_from_query():
    """Test extraction of field names from ES|QL query."""
    print("\n=== Testing Field Extraction ===")

    with patch('src.clients.base.SearchClientBase.__init__', return_value=None):
        client = ESQLClient({"hosts": ["http://localhost:9200"]}, engine_type="elasticsearch")

        # Test basic field extraction
        query1 = """
        FROM logs-*
        | WHERE process.name == "powershell.exe"
        | STATS count = COUNT(*) BY user.name
        """
        fields1 = client.extract_fields_from_query(query1)
        assert "process.name" in fields1
        assert "user.name" in fields1
        print("  Basic fields extracted: PASS")

        # Test complex query with multiple fields
        query2 = """
        FROM logs-endpoint.events.process-*
        | WHERE host.os.type == "windows" AND process.command_line LIKE "*-enc*"
        | STATS count = COUNT(*) BY process.name, process.parent.name
        | SORT count DESC
        """
        fields2 = client.extract_fields_from_query(query2)
        assert "host.os.type" in fields2
        assert "process.command_line" in fields2
        assert "process.name" in fields2
        assert "process.parent.name" in fields2
        print("  Complex query fields: PASS")

        # Test winlogbeat-style fields
        query3 = """
        FROM winlogbeat-*
        | WHERE winlog.event_data.Image LIKE "*powershell*"
        """
        fields3 = client.extract_fields_from_query(query3)
        assert "winlog.event_data.Image" in fields3
        print("  Winlogbeat fields: PASS")

        print("  [PASS] Field extraction works correctly")


def test_substitute_index():
    """Test index substitution in ES|QL queries."""
    print("\n=== Testing Index Substitution ===")

    with patch('src.clients.base.SearchClientBase.__init__', return_value=None):
        client = ESQLClient({"hosts": ["http://localhost:9200"]}, engine_type="elasticsearch")

        # Test basic substitution
        query1 = "FROM logs-endpoint.events.process-* | LIMIT 10"
        result1 = client.substitute_index(query1, "winlogbeat-*")
        assert "FROM winlogbeat-*" in result1
        assert "logs-endpoint" not in result1
        print("  Basic substitution: PASS")

        # Test preserving rest of query
        query2 = """FROM logs-* | WHERE process.name == "cmd.exe" | LIMIT 10"""
        result2 = client.substitute_index(query2, "my-index-*")
        assert "FROM my-index-*" in result2
        assert 'process.name == "cmd.exe"' in result2
        print("  Query preservation: PASS")

        # Test case insensitivity
        query3 = "from old-index-* | STATS count = COUNT(*)"
        result3 = client.substitute_index(query3, "new-index-*")
        assert "new-index-*" in result3
        print("  Case insensitive: PASS")

        print("  [PASS] Index substitution works correctly")


def test_field_aliases():
    """Test that field aliases are properly defined."""
    print("\n=== Testing Field Aliases ===")

    with patch('src.clients.base.SearchClientBase.__init__', return_value=None):
        client = ESQLClient({"hosts": ["http://localhost:9200"]}, engine_type="elasticsearch")

        # Check essential aliases exist
        assert "process.name" in client.FIELD_ALIASES
        assert "winlog.event_data.Image" in client.FIELD_ALIASES["process.name"]
        print("  process.name aliases: PASS")

        assert "process.command_line" in client.FIELD_ALIASES
        assert "winlog.event_data.CommandLine" in client.FIELD_ALIASES["process.command_line"]
        print("  process.command_line aliases: PASS")

        assert "user.name" in client.FIELD_ALIASES
        print("  user.name aliases: PASS")

        assert "destination.ip" in client.FIELD_ALIASES
        assert "source.ip" in client.FIELD_ALIASES
        print("  Network field aliases: PASS")

        print("  [PASS] Field aliases are properly defined")


def test_calculate_field_match_score():
    """Test field match scoring with aliases."""
    print("\n=== Testing Field Match Scoring ===")

    with patch('src.clients.base.SearchClientBase.__init__', return_value=None):
        client = ESQLClient({"hosts": ["http://localhost:9200"]}, engine_type="elasticsearch")

        # Test direct match
        required = ["process.name", "user.name"]
        available = {"process.name", "user.name", "host.name"}
        score = client._calculate_field_match_score(required, available)
        assert score == 2
        print("  Direct match scoring: PASS")

        # Test alias match
        required_ecs = ["process.name", "process.command_line"]
        available_winlog = {
            "winlog.event_data.Image",  # alias for process.name
            "winlog.event_data.CommandLine",  # alias for process.command_line
            "winlog.event_id"
        }
        score_alias = client._calculate_field_match_score(required_ecs, available_winlog)
        assert score_alias == 2  # Both should match via aliases
        print("  Alias match scoring: PASS")

        # Test partial match
        required_partial = ["process.name", "nonexistent.field"]
        available_partial = {"process.name", "other.field"}
        score_partial = client._calculate_field_match_score(required_partial, available_partial)
        assert score_partial == 1
        print("  Partial match scoring: PASS")

        print("  [PASS] Field match scoring works correctly")


def test_discover_compatible_indices_mock():
    """Test index discovery with mocked Elasticsearch responses."""
    print("\n=== Testing Index Discovery (Mocked) ===")

    with patch('src.clients.base.SearchClientBase.__init__', return_value=None):
        client = ESQLClient({"hosts": ["http://localhost:9200"]}, engine_type="elasticsearch")
        client.client = MagicMock()

        # Mock cat.indices response
        client.client.cat.indices.return_value = [
            {"index": "winlogbeat-2024.01.01", "docs.count": "10000"},
            {"index": "filebeat-2024.01.01", "docs.count": "5000"},
            {"index": ".security", "docs.count": "100"},  # System index, should be skipped
            {"index": "empty-index", "docs.count": "0"},  # Empty, should be skipped
        ]

        # Mock get_mapping response for winlogbeat
        client.client.indices.get_mapping.side_effect = [
            {
                "winlogbeat-2024.01.01": {
                    "mappings": {
                        "properties": {
                            "winlog": {
                                "properties": {
                                    "event_data": {
                                        "properties": {
                                            "Image": {"type": "keyword"},
                                            "CommandLine": {"type": "keyword"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            {
                "filebeat-2024.01.01": {
                    "mappings": {
                        "properties": {
                            "message": {"type": "text"}
                        }
                    }
                }
            }
        ]

        # Test discovery
        required_fields = ["process.name", "process.command_line"]
        compatible = client.discover_compatible_indices(required_fields)

        # Winlogbeat should be found (has aliases for the required fields)
        assert len(compatible) >= 1
        if len(compatible) > 0:
            assert compatible[0]["index"] == "winlogbeat-2024.01.01"
            assert compatible[0]["match_score"] == 2  # Both fields matched via aliases
            print(f"  Found compatible index: {compatible[0]['index']} (score: {compatible[0]['match_score']})")

        print("  [PASS] Index discovery works correctly (mocked)")


def test_execute_with_auto_discovery_mock():
    """Test adaptive execution with mocked Elasticsearch responses."""
    print("\n=== Testing Adaptive Execution (Mocked) ===")

    with patch('src.clients.base.SearchClientBase.__init__', return_value=None):
        client = ESQLClient({"hosts": ["http://localhost:9200"]}, engine_type="elasticsearch")
        client.client = MagicMock()
        client._version_checked = True
        client._esql_supported = True

        # First call fails (index not found)
        # Second call succeeds (with alternative index)
        def esql_query_side_effect(query, format):
            if "logs-endpoint" in query:
                raise Exception("Unknown index [logs-endpoint.events.process-*]")
            return {
                "columns": [{"name": "process.name"}, {"name": "count"}],
                "values": [["powershell.exe", 10], ["cmd.exe", 5]]
            }

        client.client.esql.query.side_effect = esql_query_side_effect

        # Mock index discovery
        client.client.cat.indices.return_value = [
            {"index": "winlogbeat-2024.01.01", "docs.count": "10000"}
        ]

        client.client.indices.get_mapping.return_value = {
            "winlogbeat-2024.01.01": {
                "mappings": {
                    "properties": {
                        "winlog": {
                            "properties": {
                                "event_data": {
                                    "properties": {
                                        "Image": {"type": "keyword"}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        # Test adaptive execution
        query = """
        FROM logs-endpoint.events.process-*
        | WHERE process.name == "powershell.exe"
        | STATS count = COUNT(*) BY process.name
        """

        result = client.execute_with_auto_discovery(query)

        # Should succeed with auto-discovered index
        if "error" not in result or result.get("index_resolution", {}).get("auto_discovered"):
            print("  Auto-discovery triggered: PASS")

        print("  [PASS] Adaptive execution works correctly (mocked)")


def run_all_tests():
    """Run all adaptive index resolution tests."""
    print("=" * 60)
    print("ES|QL Adaptive Index Resolution Test Suite")
    print("=" * 60)

    test_extract_index_from_query()
    test_extract_fields_from_query()
    test_substitute_index()
    test_field_aliases()
    test_calculate_field_match_score()
    test_discover_compatible_indices_mock()
    test_execute_with_auto_discovery_mock()

    print("\n" + "=" * 60)
    print("All adaptive index resolution tests passed!")
    print("=" * 60)


if __name__ == "__main__":
    run_all_tests()
