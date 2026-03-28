"""Test hunting rule loader functionality."""

import shutil
import sys
import tempfile
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.clients.common.hunting_rule_loader import HuntingRule, HuntingRuleLoader


def create_test_hunting_directory():
    """Create a temporary directory with test hunting TOML files."""
    test_dir = Path(tempfile.mkdtemp(prefix="hunting_test_"))

    # Create platform directories
    (test_dir / "windows" / "queries").mkdir(parents=True)
    (test_dir / "linux" / "queries").mkdir(parents=True)

    # Create a Windows ES|QL hunting rule
    windows_rule = """
[hunt]
author = "Test"
description = "Test hunting rule for suspicious PowerShell commands"
integration = ["endpoint", "windows"]
uuid = "test-uuid-001"
name = "Suspicious PowerShell Command"
language = ["ES|QL"]
license = "Elastic License v2"
notes = [
    "This is a test note",
    "Another test note"
]
mitre = ["T1059", "T1059.001"]
query = [
\'\'\'
FROM logs-endpoint.events.process-*
| WHERE host.os.type == "windows" and process.name == "powershell.exe"
| STATS count = COUNT(*) BY process.command_line
| SORT count DESC
| LIMIT 20
\'\'\'
]
"""
    (test_dir / "windows" / "queries" / "powershell_hunting.toml").write_text(windows_rule)

    # Create a Linux ES|QL hunting rule with multiple queries
    linux_rule = """
[hunt]
author = "Test"
description = "Test hunting rule for cron persistence"
integration = ["endpoint"]
uuid = "test-uuid-002"
name = "Cron Persistence Detection"
language = ["ES|QL", "EQL"]
license = "Elastic License v2"
notes = ["Check for unusual cron entries"]
mitre = ["T1053", "T1053.003"]
query = [
\'\'\'
FROM logs-endpoint.events.file-*
| WHERE host.os.type == "linux" and file.path LIKE "/etc/cron*"
| STATS count = COUNT(*) BY file.path, process.executable
| SORT count DESC
\'\'\'
,
\'\'\'
process where process.name == "crontab" and process.args == "-e"
\'\'\'
]
"""
    (test_dir / "linux" / "queries" / "cron_persistence.toml").write_text(linux_rule)

    # Create a rule with only EQL (no ES|QL) - should be skipped
    eql_only_rule = """
[hunt]
author = "Test"
description = "EQL only rule"
integration = ["endpoint"]
uuid = "test-uuid-003"
name = "EQL Only Rule"
language = ["EQL"]
license = "Elastic License v2"
mitre = ["T1055"]
query = [
\'\'\'
process where process.name == "regsvr32.exe"
\'\'\'
]
"""
    (test_dir / "windows" / "queries" / "eql_only.toml").write_text(eql_only_rule)

    return test_dir


def test_loads_esql_queries_only():
    """Test that only ES|QL queries are loaded."""
    print("\n=== Testing ES|QL Query Loading ===")

    test_dir = create_test_hunting_directory()

    try:
        loader = HuntingRuleLoader(str(test_dir))

        # Should have 2 rules (the EQL-only rule should be skipped)
        assert len(loader.rules) == 2, f"Expected 2 rules, got {len(loader.rules)}"

        # Check that the EQL-only rule was skipped
        assert "test-uuid-003" not in loader.rules

        print(f"  Loaded {len(loader.rules)} rules")
        print("  EQL-only rule correctly skipped")
        print("  [PASS] Only ES|QL queries are loaded")

    finally:
        shutil.rmtree(test_dir)


def test_filters_by_platform():
    """Test filtering rules by platform."""
    print("\n=== Testing Platform Filtering ===")

    test_dir = create_test_hunting_directory()

    try:
        loader = HuntingRuleLoader(str(test_dir))

        # Search for Windows rules
        windows_rules = loader.search_rules(platform="windows")
        assert len(windows_rules) == 1
        assert windows_rules[0].platform == "windows"

        # Search for Linux rules
        linux_rules = loader.search_rules(platform="linux")
        assert len(linux_rules) == 1
        assert linux_rules[0].platform == "linux"

        print(f"  Windows rules: {len(windows_rules)}")
        print(f"  Linux rules: {len(linux_rules)}")
        print("  [PASS] Platform filtering works")

    finally:
        shutil.rmtree(test_dir)


def test_filters_by_mitre():
    """Test filtering rules by MITRE technique."""
    print("\n=== Testing MITRE Filtering ===")

    test_dir = create_test_hunting_directory()

    try:
        loader = HuntingRuleLoader(str(test_dir))

        # Search for T1059 (PowerShell rule)
        t1059_rules = loader.search_rules(mitre="T1059")
        assert len(t1059_rules) == 1
        assert "T1059" in t1059_rules[0].mitre

        # Search for T1053 (Cron rule)
        t1053_rules = loader.search_rules(mitre="T1053")
        assert len(t1053_rules) == 1
        assert "T1053" in t1053_rules[0].mitre

        print(f"  T1059 rules: {len(t1059_rules)}")
        print(f"  T1053 rules: {len(t1053_rules)}")
        print("  [PASS] MITRE filtering works")

    finally:
        shutil.rmtree(test_dir)


def test_filters_by_keyword():
    """Test filtering rules by keyword search."""
    print("\n=== Testing Keyword Search ===")

    test_dir = create_test_hunting_directory()

    try:
        loader = HuntingRuleLoader(str(test_dir))

        # Search for "PowerShell"
        ps_rules = loader.search_rules(keyword="PowerShell")
        assert len(ps_rules) == 1
        assert "PowerShell" in ps_rules[0].name

        # Search for "cron"
        cron_rules = loader.search_rules(keyword="cron")
        assert len(cron_rules) == 1

        # Search for non-existent keyword
        no_rules = loader.search_rules(keyword="nonexistent")
        assert len(no_rules) == 0

        print(f"  'PowerShell' search: {len(ps_rules)} rules")
        print(f"  'cron' search: {len(cron_rules)} rules")
        print("  [PASS] Keyword search works")

    finally:
        shutil.rmtree(test_dir)


def test_detects_eql_vs_esql():
    """Test detection of EQL vs ES|QL queries."""
    print("\n=== Testing EQL vs ES|QL Detection ===")

    test_dir = create_test_hunting_directory()

    try:
        loader = HuntingRuleLoader(str(test_dir))

        # Test ES|QL detection
        esql_query = "FROM logs-* | LIMIT 10"
        assert loader._is_esql(esql_query) is True

        esql_query2 = "from logs-endpoint.events.* | where @timestamp > now() - 1 day"
        assert loader._is_esql(esql_query2) is True

        # Test EQL detection (should NOT be ES|QL)
        eql_query1 = "process where process.name == 'cmd.exe'"
        assert loader._is_esql(eql_query1) is False

        eql_query2 = "file where file.path like '/etc/*'"
        assert loader._is_esql(eql_query2) is False

        eql_query3 = "sequence [process where true] [network where true]"
        assert loader._is_esql(eql_query3) is False

        # Test SQL/OSQuery detection (should NOT be ES|QL)
        sql_query = "SELECT * FROM processes"
        assert loader._is_esql(sql_query) is False

        print("  ES|QL queries detected: PASS")
        print("  EQL queries not detected as ES|QL: PASS")
        print("  SQL queries not detected as ES|QL: PASS")
        print("  [PASS] EQL vs ES|QL detection works")

    finally:
        shutil.rmtree(test_dir)


def test_rule_properties():
    """Test that rule properties are correctly parsed."""
    print("\n=== Testing Rule Properties ===")

    test_dir = create_test_hunting_directory()

    try:
        loader = HuntingRuleLoader(str(test_dir))

        # Get the Windows rule
        rule = loader.get_rule("test-uuid-001")

        assert rule is not None
        assert rule.uuid == "test-uuid-001"
        assert rule.name == "Suspicious PowerShell Command"
        assert "Test hunting rule" in rule.description
        assert rule.platform == "windows"
        assert "endpoint" in rule.integration
        assert "T1059" in rule.mitre
        assert len(rule.notes) == 2
        assert len(rule.esql_queries) == 1

        print(f"  UUID: {rule.uuid}")
        print(f"  Name: {rule.name}")
        print(f"  Platform: {rule.platform}")
        print(f"  MITRE: {rule.mitre}")
        print(f"  ES|QL queries: {len(rule.esql_queries)}")
        print("  [PASS] Rule properties correctly parsed")

    finally:
        shutil.rmtree(test_dir)


def test_rule_with_multiple_queries():
    """Test rules with multiple ES|QL queries."""
    print("\n=== Testing Multiple Queries ===")

    test_dir = create_test_hunting_directory()

    try:
        loader = HuntingRuleLoader(str(test_dir))

        # Get the Linux rule which has both ES|QL and EQL
        rule = loader.get_rule("test-uuid-002")

        # Should only have 1 ES|QL query (the EQL one should be filtered out)
        assert len(rule.esql_queries) == 1
        assert rule.esql_queries[0].strip().startswith("FROM")

        # The original query list should have both
        assert len(rule.query) == 2

        print(f"  Total queries in rule: {len(rule.query)}")
        print(f"  ES|QL queries extracted: {len(rule.esql_queries)}")
        print("  [PASS] Multiple queries handled correctly")

    finally:
        shutil.rmtree(test_dir)


def test_statistics():
    """Test rule statistics generation."""
    print("\n=== Testing Statistics ===")

    test_dir = create_test_hunting_directory()

    try:
        loader = HuntingRuleLoader(str(test_dir))

        stats = loader.get_statistics()

        assert stats["total_rules"] == 2
        assert stats["total_esql_queries"] == 2  # 1 from each rule
        assert "windows" in stats["platforms"]
        assert "linux" in stats["platforms"]

        print(f"  Total rules: {stats['total_rules']}")
        print(f"  Total ES|QL queries: {stats['total_esql_queries']}")
        print(f"  Platforms: {list(stats['platforms'].keys())}")
        print("  [PASS] Statistics generation works")

    finally:
        shutil.rmtree(test_dir)


def test_platform_detection():
    """Test platform detection from file path."""
    print("\n=== Testing Platform Detection ===")

    test_dir = create_test_hunting_directory()

    try:
        loader = HuntingRuleLoader(str(test_dir))

        # Test Windows path detection
        windows_path = test_dir / "windows" / "queries" / "test.toml"
        assert loader._detect_platform(windows_path) == "windows"

        # Test Linux path detection
        linux_path = test_dir / "linux" / "queries" / "test.toml"
        assert loader._detect_platform(linux_path) == "linux"

        # Test unknown path
        unknown_path = test_dir / "unknown" / "queries" / "test.toml"
        assert loader._detect_platform(unknown_path) == "unknown"

        print("  Windows path detected: PASS")
        print("  Linux path detected: PASS")
        print("  Unknown path handled: PASS")
        print("  [PASS] Platform detection works")

    finally:
        shutil.rmtree(test_dir)


def test_short_description():
    """Test short description truncation."""
    print("\n=== Testing Short Description ===")

    rule = HuntingRule(
        uuid="test",
        name="Test",
        description="A" * 250,  # Long description
        query=[],
        platform="windows",
        integration=[],
        mitre=[],
        notes=[],
        file_path="/test",
        esql_queries=[],
    )

    short = rule.short_description
    assert len(short) <= 200
    assert short.endswith("...")

    # Test short description that doesn't need truncation
    rule2 = HuntingRule(
        uuid="test",
        name="Test",
        description="Short description",
        query=[],
        platform="windows",
        integration=[],
        mitre=[],
        notes=[],
        file_path="/test",
        esql_queries=[],
    )

    assert rule2.short_description == "Short description"
    assert not rule2.short_description.endswith("...")

    print("  Long description truncated: PASS")
    print("  Short description unchanged: PASS")
    print("  [PASS] Short description works")


def test_get_platforms_and_techniques():
    """Test getting available platforms and MITRE techniques."""
    print("\n=== Testing Available Platforms/Techniques ===")

    test_dir = create_test_hunting_directory()

    try:
        loader = HuntingRuleLoader(str(test_dir))

        platforms = loader.get_platforms()
        assert "windows" in platforms
        assert "linux" in platforms

        techniques = loader.get_mitre_techniques()
        assert "T1059" in techniques or "T1059.001" in techniques
        assert "T1053" in techniques or "T1053.003" in techniques

        print(f"  Platforms: {platforms}")
        print(f"  Techniques: {techniques}")
        print("  [PASS] Platform and technique listing works")

    finally:
        shutil.rmtree(test_dir)


def test_missing_directory():
    """Test handling of missing hunting directory."""
    print("\n=== Testing Missing Directory ===")

    loader = HuntingRuleLoader("/nonexistent/path")

    assert len(loader.rules) == 0
    stats = loader.get_statistics()
    assert stats["total_rules"] == 0

    print("  Missing directory handled gracefully")
    print("  [PASS] Missing directory handling works")


def run_all_tests():
    """Run all hunting rule loader tests."""
    print("=" * 60)
    print("Hunting Rule Loader Test Suite")
    print("=" * 60)

    test_loads_esql_queries_only()
    test_filters_by_platform()
    test_filters_by_mitre()
    test_filters_by_keyword()
    test_detects_eql_vs_esql()
    test_rule_properties()
    test_rule_with_multiple_queries()
    test_statistics()
    test_platform_detection()
    test_short_description()
    test_get_platforms_and_techniques()
    test_missing_directory()

    print("\n" + "=" * 60)
    print("All hunting rule loader tests passed!")
    print("=" * 60)


if __name__ == "__main__":
    run_all_tests()
