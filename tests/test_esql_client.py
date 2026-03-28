"""Test ES|QL client functionality."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.clients.common.esql_client import ESQLClient, ESQLNotSupportedError


def test_version_check_passes_8_11():
    """Test version check passes for ES 8.11+."""
    print("\n=== Testing Version Check (8.11+) ===")

    config = {"hosts": ["http://localhost:9200"]}

    # Mock the ES client
    with patch("src.clients.base.SearchClientBase.__init__", return_value=None):
        client = ESQLClient(config, engine_type="elasticsearch")
        client.client = MagicMock()
        client.client.info.return_value = {"version": {"number": "8.15.0"}}

        # This should not raise
        client.check_version()

        assert client._esql_supported is True
        assert client._version_checked is True
        assert client.es_version == "8.15.0"

        print("  ES version: 8.15.0")
        print("  ES|QL supported: True")
        print("  [PASS] Version check passes for 8.15.0")


def test_version_check_fails_8_10():
    """Test version check fails for ES < 8.11."""
    print("\n=== Testing Version Check (8.10) ===")

    config = {"hosts": ["http://localhost:9200"]}

    with patch("src.clients.base.SearchClientBase.__init__", return_value=None):
        client = ESQLClient(config, engine_type="elasticsearch")
        client.client = MagicMock()
        client.client.info.return_value = {"version": {"number": "8.10.0"}}

        try:
            client.check_version()
            assert False, "Should have raised ESQLNotSupportedError"
        except ESQLNotSupportedError as e:
            assert "8.11" in str(e)
            assert "8.10.0" in str(e)
            print(f"  Error message: {e}")
            print("  [PASS] Version check correctly rejects 8.10.0")


def test_version_check_fails_7_x():
    """Test version check fails for ES 7.x."""
    print("\n=== Testing Version Check (7.17) ===")

    config = {"hosts": ["http://localhost:9200"]}

    with patch("src.clients.base.SearchClientBase.__init__", return_value=None):
        client = ESQLClient(config, engine_type="elasticsearch")
        client.client = MagicMock()
        client.client.info.return_value = {"version": {"number": "7.17.0"}}

        try:
            client.check_version()
            assert False, "Should have raised ESQLNotSupportedError"
        except ESQLNotSupportedError as e:
            assert "8.11" in str(e)
            print(f"  Error message: {e}")
            print("  [PASS] Version check correctly rejects 7.17.0")


def test_opensearch_rejected():
    """Test that OpenSearch is rejected for ES|QL."""
    print("\n=== Testing OpenSearch Rejection ===")

    config = {"hosts": ["http://localhost:9200"]}

    try:
        with patch("src.clients.base.SearchClientBase.__init__", return_value=None):
            client = ESQLClient(config, engine_type="opensearch")
            assert False, "Should have raised ESQLNotSupportedError"
    except ESQLNotSupportedError as e:
        assert "OpenSearch" in str(e)
        print(f"  Error message: {e}")
        print("  [PASS] OpenSearch correctly rejected")


def test_extract_index_single():
    """Test extracting single index from FROM clause."""
    print("\n=== Testing Extract Index (Single) ===")

    config = {"hosts": ["http://localhost:9200"]}

    with patch("src.clients.base.SearchClientBase.__init__", return_value=None):
        client = ESQLClient(config, engine_type="elasticsearch")

        # Single index
        q1 = "FROM winlogbeat-* | WHERE x == 1"
        result = client.extract_index_from_query(q1)
        assert result == "winlogbeat-*", f"Expected 'winlogbeat-*', got '{result}'"
        print(f"  Single index: '{result}' [PASS]")

        # Single index with METADATA
        q2 = "FROM logs-* METADATA _id | LIMIT 10"
        result = client.extract_index_from_query(q2)
        assert result == "logs-*", f"Expected 'logs-*', got '{result}'"
        print(f"  With METADATA: '{result}' [PASS]")

        # Single index no pipe
        q3 = "from single-index"
        result = client.extract_index_from_query(q3)
        assert result == "single-index", f"Expected 'single-index', got '{result}'"
        print(f"  No pipe: '{result}' [PASS]")


def test_extract_index_multi():
    """Test extracting multiple comma-separated indices from FROM clause."""
    print("\n=== Testing Extract Index (Multi-Index) ===")

    config = {"hosts": ["http://localhost:9200"]}

    with patch("src.clients.base.SearchClientBase.__init__", return_value=None):
        client = ESQLClient(config, engine_type="elasticsearch")

        # Multi-index with spaces after comma (the bug case!)
        q1 = "FROM logs-endpoint.events.process-*, logs-windows.sysmon_operational-*, logs-system.security-*"
        result = client.extract_index_from_query(q1)
        expected = "logs-endpoint.events.process-*, logs-windows.sysmon_operational-*, logs-system.security-*"
        assert result == expected, f"Expected '{expected}', got '{result}'"
        print("  Multi-index (spaces): [PASS]")

        # Multi-index without spaces
        q2 = "FROM idx1,idx2,idx3 | LIMIT 10"
        result = client.extract_index_from_query(q2)
        assert result == "idx1,idx2,idx3", f"Expected 'idx1,idx2,idx3', got '{result}'"
        print(f"  Multi-index (no spaces): '{result}' [PASS]")

        # Multi-index with newline before pipe
        q3 = """from logs-endpoint.events.process-*, logs-windows.sysmon_operational-*
| where host.os.type == "windows" """
        result = client.extract_index_from_query(q3)
        assert "logs-endpoint" in result and "logs-windows" in result
        print("  Multi-index (newline): [PASS]")


def test_substitute_index_single():
    """Test substituting single index in FROM clause."""
    print("\n=== Testing Substitute Index (Single) ===")

    config = {"hosts": ["http://localhost:9200"]}

    with patch("src.clients.base.SearchClientBase.__init__", return_value=None):
        client = ESQLClient(config, engine_type="elasticsearch")

        # Single index
        q1 = "FROM winlogbeat-* | WHERE x == 1"
        result = client.substitute_index(q1, "NEW-INDEX")
        assert result.startswith("FROM NEW-INDEX |"), f"Got: {result}"
        assert "winlogbeat" not in result
        print("  Single index substituted: [PASS]")

        # With METADATA
        q2 = "FROM logs-* METADATA _id | LIMIT 10"
        result = client.substitute_index(q2, "NEW-INDEX")
        assert "FROM NEW-INDEX METADATA" in result or "FROM NEW-INDEX " in result
        assert "logs-*" not in result
        print("  With METADATA: [PASS]")


def test_substitute_index_multi():
    """Test substituting multi-index FROM clause - THE BUG CASE."""
    print("\n=== Testing Substitute Index (Multi-Index) ===")

    config = {"hosts": ["http://localhost:9200"]}

    with patch("src.clients.base.SearchClientBase.__init__", return_value=None):
        client = ESQLClient(config, engine_type="elasticsearch")

        # Multi-index with spaces after comma - THIS WAS THE BUG!
        q1 = """from logs-endpoint.events.process-*, logs-windows.sysmon_operational-*, logs-system.security-*
| where host.os.type == "windows" """
        result = client.substitute_index(q1, "winlogbeat-*")

        # CRITICAL: The result must NOT contain any of the original indices!
        assert "logs-endpoint" not in result, f"Original index not replaced! Got: {result}"
        assert "logs-windows" not in result, f"Original index not replaced! Got: {result}"
        assert "logs-system" not in result, f"Original index not replaced! Got: {result}"
        assert result.lower().startswith("from winlogbeat-*"), f"New index not at start! Got: {result}"
        print("  Multi-index (spaces) ALL replaced: [PASS]")

        # Multi-index without spaces
        q2 = "FROM idx1,idx2,idx3 | LIMIT 10"
        result = client.substitute_index(q2, "NEW-INDEX")
        assert "idx1" not in result
        assert "idx2" not in result
        assert "idx3" not in result
        assert "FROM NEW-INDEX |" in result
        print("  Multi-index (no spaces) ALL replaced: [PASS]")

        # Verify WHERE clause preserved
        assert "host.os.type" in result or "LIMIT" in result
        print("  WHERE clause preserved: [PASS]")


def test_timeframe_substitution():
    """Test timeframe substitution in queries."""
    print("\n=== Testing Timeframe Substitution ===")

    config = {"hosts": ["http://localhost:9200"]}

    with patch("src.clients.base.SearchClientBase.__init__", return_value=None):
        client = ESQLClient(config, engine_type="elasticsearch")

        # Test basic substitution
        query1 = "FROM logs-* | WHERE @timestamp > now() - 30 day | LIMIT 10"
        result1 = client.substitute_timeframe(query1, 7)
        assert "@timestamp > now() - 7 day" in result1
        print("  Original: ...now() - 30 day...")
        print("  Modified: ...now() - 7 day...")

        # Test with different spacing
        query2 = "FROM logs-* | WHERE @timestamp>now()-14 day | LIMIT 10"
        result2 = client.substitute_timeframe(query2, 3)
        assert "@timestamp > now() - 3 day" in result2
        print("  [PASS] Timeframe substitution works with varied spacing")

        # Test case insensitivity
        query3 = "FROM logs-* | WHERE @TIMESTAMP > NOW() - 60 DAY | LIMIT 10"
        result3 = client.substitute_timeframe(query3, 1)
        assert "now() - 1 day" in result3.lower()
        print("  [PASS] Timeframe substitution is case insensitive")


def test_clean_query():
    """Test query cleaning (removes comments, normalizes whitespace)."""
    print("\n=== Testing Query Cleaning ===")

    config = {"hosts": ["http://localhost:9200"]}

    with patch("src.clients.base.SearchClientBase.__init__", return_value=None):
        client = ESQLClient(config, engine_type="elasticsearch")

        # Test removing single-line comments
        query1 = "FROM logs-* // this is a comment\n| LIMIT 10"
        result1 = client._clean_query(query1)
        assert "//" not in result1
        assert "comment" not in result1
        print("  Single-line comments removed: PASS")

        # Test removing multi-line comments
        query2 = "FROM logs-* /* multi\nline\ncomment */ | LIMIT 10"
        result2 = client._clean_query(query2)
        assert "/*" not in result2
        assert "*/" not in result2
        print("  Multi-line comments removed: PASS")

        # Test whitespace normalization
        query3 = "FROM   logs-*   |   LIMIT   10"
        result3 = client._clean_query(query3)
        assert "  " not in result3  # No double spaces
        print("  Whitespace normalized: PASS")
        print("  [PASS] Query cleaning works correctly")


def test_token_counting():
    """Test token count estimation."""
    print("\n=== Testing Token Counting ===")

    config = {"hosts": ["http://localhost:9200"]}

    with patch("src.clients.base.SearchClientBase.__init__", return_value=None):
        client = ESQLClient(config, engine_type="elasticsearch")

        # Test token counting (4 chars = 1 token)
        result = {"results": [{"process.name": "powershell.exe", "count": 10}, {"process.name": "cmd.exe", "count": 5}]}

        tokens = client._count_tokens(result)

        # JSON string of results is ~80 chars, so ~20 tokens
        assert tokens > 0
        assert tokens < 100  # Sanity check
        print(f"  Results: {result['results']}")
        print(f"  Estimated tokens: {tokens}")
        print("  [PASS] Token counting works")


def test_parse_response():
    """Test ES|QL response parsing."""
    print("\n=== Testing Response Parsing ===")

    config = {"hosts": ["http://localhost:9200"]}

    with patch("src.clients.base.SearchClientBase.__init__", return_value=None):
        client = ESQLClient(config, engine_type="elasticsearch")

        # Mock ES|QL response format
        mock_response = {
            "columns": [{"name": "process.name", "type": "keyword"}, {"name": "count", "type": "long"}],
            "values": [["powershell.exe", 10], ["cmd.exe", 5], ["python.exe", 3]],
        }

        result = client._parse_response(mock_response)

        assert result["hits_count"] == 3
        assert result["columns"] == ["process.name", "count"]
        assert len(result["results"]) == 3
        assert result["results"][0]["process.name"] == "powershell.exe"
        assert result["results"][0]["count"] == 10

        print(f"  Hits count: {result['hits_count']}")
        print(f"  Columns: {result['columns']}")
        print(f"  First result: {result['results'][0]}")
        print("  [PASS] Response parsing works correctly")


def test_lean_mode_summarization():
    """Test lean mode result summarization."""
    print("\n=== Testing Lean Mode Summarization ===")

    config = {"hosts": ["http://localhost:9200"]}

    with patch("src.clients.base.SearchClientBase.__init__", return_value=None):
        client = ESQLClient(config, engine_type="elasticsearch")

        # Create a result with many rows
        result = {
            "hits_count": 100,
            "tokens_used": 3000,
            "columns": ["process.name", "count"],
            "results": [
                {"process.name": "powershell.exe", "count": 50},
                {"process.name": "cmd.exe", "count": 30},
                {"process.name": "python.exe", "count": 10},
                {"process.name": "node.exe", "count": 5},
                {"process.name": "ruby.exe", "count": 3},
                {"process.name": "perl.exe", "count": 2},
            ]
            * 10,  # 60 rows
        }

        summarized = client._summarize(result)

        # Should have summary with top values
        assert "summary" in summarized
        assert "sample_results" in summarized
        assert len(summarized["sample_results"]) <= 5  # Max 5 sample results
        assert summarized["tokens_used"] < result["tokens_used"]  # Lean uses fewer tokens

        print(f"  Original tokens: {result['tokens_used']}")
        print(f"  Lean tokens: {summarized['tokens_used']}")
        print(f"  Sample results count: {len(summarized['sample_results'])}")
        print(f"  Summary keys: {list(summarized['summary'].keys())}")
        print("  [PASS] Lean mode summarization works correctly")


def test_execution_tracking():
    """Test query execution history tracking."""
    print("\n=== Testing Execution Tracking ===")

    config = {"hosts": ["http://localhost:9200"]}

    with patch("src.clients.base.SearchClientBase.__init__", return_value=None):
        client = ESQLClient(config, engine_type="elasticsearch")

        # Track a few executions
        result1 = {"tokens_used": 100, "hits_count": 5, "execution_time_ms": 50}
        client._track_execution("rule-1", "FROM logs-* | LIMIT 5", result1)

        result2 = {"tokens_used": 200, "hits_count": 10, "execution_time_ms": 100}
        client._track_execution("rule-2", "FROM logs-* | LIMIT 10", result2)

        history = client.get_execution_history()

        assert len(history) == 2
        assert history[0]["rule_id"] == "rule-1"
        assert history[1]["rule_id"] == "rule-2"
        assert history[0]["result_tokens"] == 100
        assert history[1]["result_tokens"] == 200

        print(f"  Tracked executions: {len(history)}")
        print(f"  First execution: rule_id={history[0]['rule_id']}, tokens={history[0]['result_tokens']}")
        print("  [PASS] Execution tracking works correctly")


def test_execution_history_limit():
    """Test that execution history is limited to 100 entries."""
    print("\n=== Testing Execution History Limit ===")

    config = {"hosts": ["http://localhost:9200"]}

    with patch("src.clients.base.SearchClientBase.__init__", return_value=None):
        client = ESQLClient(config, engine_type="elasticsearch")

        # Add 150 executions
        for i in range(150):
            result = {"tokens_used": i, "hits_count": 1, "execution_time_ms": 10}
            client._track_execution(f"rule-{i}", f"query-{i}", result)

        history = client.get_execution_history()

        assert len(history) == 100  # Should be capped at 100
        assert history[0]["rule_id"] == "rule-50"  # First 50 should be dropped

        print(f"  Added 150 executions, history length: {len(history)}")
        print("  First entry is rule-50 (oldest 50 dropped): PASS")
        print("  [PASS] Execution history limit works correctly")


def run_all_tests():
    """Run all ES|QL client tests."""
    print("=" * 60)
    print("ES|QL Client Test Suite")
    print("=" * 60)

    test_version_check_passes_8_11()
    test_version_check_fails_8_10()
    test_version_check_fails_7_x()
    test_opensearch_rejected()
    test_extract_index_single()
    test_extract_index_multi()
    test_substitute_index_single()
    test_substitute_index_multi()
    test_timeframe_substitution()
    test_clean_query()
    test_token_counting()
    test_parse_response()
    test_lean_mode_summarization()
    test_execution_tracking()
    test_execution_history_limit()

    print("\n" + "=" * 60)
    print("All ES|QL client tests passed!")
    print("=" * 60)


if __name__ == "__main__":
    run_all_tests()
