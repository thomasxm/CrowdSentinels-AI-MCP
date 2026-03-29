"""Test MCP Investigation State Tools."""

import shutil
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.storage.config import StorageConfig, set_config


def setup_test_environment():
    """Set up test environment with clean storage."""
    # Use a test directory
    test_path = Path("/tmp/crowdsentinel-mcp-test")
    if test_path.exists():
        shutil.rmtree(test_path)

    config = StorageConfig(base_path=test_path)
    set_config(config)
    config.ensure_directories()
    return config


def test_investigation_state_tools():
    """Test investigation state MCP tools."""
    print("\n=== Testing MCP Investigation State Tools ===")

    # Set up clean environment
    config = setup_test_environment()

    # Import after setting config
    # Reset the shared singleton (now lives in auto_capture)
    import src.storage.auto_capture as auto_capture_module
    from src.tools.investigation_state_tools import (
        get_investigation_client,
    )

    auto_capture_module._client = None

    client = get_investigation_client()

    # Test 1: List investigations (should be empty initially)
    print("\n--- Test 1: List investigations ---")
    investigations = client.storage.list_investigations()
    print(f"  Initial investigations: {len(investigations)}")
    assert len(investigations) == 0, "Should start with no investigations"
    print("  [PASS] List investigations works")

    # Test 2: Create investigation
    print("\n--- Test 2: Create investigation ---")
    from src.storage.models import Severity

    investigation = client.create_investigation(
        name="Test MCP Investigation",
        description="Testing MCP tools",
        tags=["test", "mcp"],
        severity=Severity.HIGH,
    )
    print(f"  Created: {investigation.manifest.id}")
    assert investigation.manifest.id.startswith("INV-")
    print("  [PASS] Create investigation works")

    # Test 3: Add IoCs manually
    print("\n--- Test 3: Add IoCs manually ---")
    from src.storage.models import IoC, IoCSource, IoCType, SourceType

    ioc1 = IoC(
        type=IoCType.IP,
        value="10.0.0.50",
        sources=[IoCSource(tool="manual", source_type=SourceType.MANUAL)],
        tags=["suspicious"],
    )
    ioc2 = IoC(
        type=IoCType.DOMAIN,
        value="malware-c2.evil",
        sources=[IoCSource(tool="manual", source_type=SourceType.MANUAL)],
        tags=["c2"],
    )
    added = client.add_iocs([ioc1, ioc2])
    print(f"  Added {added} IoCs")
    assert added == 2, "Should add 2 IoCs"
    print("  [PASS] Add IoCs works")

    # Test 4: Add findings from simulated ES results
    print("\n--- Test 4: Add findings (ES simulation) ---")
    es_results = {
        "hits": {
            "total": {"value": 5},
            "hits": [
                {"_source": {"source.ip": "192.168.1.100", "user.name": "attacker"}},
                {"_source": {"destination.ip": "203.0.113.42", "host.name": "SERVER-01"}},
            ],
        }
    }
    summary = client.add_findings(
        source_type=SourceType.ELASTICSEARCH,
        source_tool="hunt_for_ioc",
        results=es_results,
        query_description="Test hunt",
    )
    print(f"  Findings: {summary}")
    assert summary["iocs_added"] > 0, "Should add IoCs from findings"
    print("  [PASS] Add findings works")

    # Test 5: Get summary
    print("\n--- Test 5: Get summary ---")
    text_summary = client.get_summary(format="compact")
    print(f"  Summary preview: {text_summary[:100]}...")
    assert investigation.manifest.id in text_summary
    print("  [PASS] Get summary works")

    # Test 6: Get shared IoCs
    print("\n--- Test 6: Get shared IoCs ---")
    shared = client.get_shared_iocs(min_priority=1, limit=50)
    print(f"  Shared IoCs: {len(shared)}")
    assert len(shared) > 0, "Should have shared IoCs"
    print("  [PASS] Get shared IoCs works")

    # Test 7: Export IoCs
    print("\n--- Test 7: Export IoCs ---")
    exported = client.export_iocs(format="json")
    print(f"  Exported {exported.get('total_iocs', 0)} IoCs")
    assert exported.get("total_iocs", 0) > 0, "Should export IoCs"
    print("  [PASS] Export IoCs works")

    # Test 8: Save and reload
    print("\n--- Test 8: Save and reload ---")
    inv_id = investigation.manifest.id
    client.save_state()

    # Reset client to simulate new session
    auto_capture_module._client = None
    client2 = get_investigation_client()

    loaded = client2.load_investigation(inv_id)
    assert loaded is not None, "Should load investigation"
    assert loaded.iocs.total_count > 0, "Should have IoCs"
    print(f"  Reloaded {loaded.iocs.total_count} IoCs")
    print("  [PASS] Save and reload works")

    # Test 9: Resume investigation
    print("\n--- Test 9: Resume investigation ---")
    resumed = client2.resume_investigation(inv_id)
    assert resumed is not None
    assert client2.active_investigation_id == inv_id
    print(f"  Resumed: {resumed.manifest.name}")
    print("  [PASS] Resume investigation works")

    # Test 10: Progressive disclosure
    print("\n--- Test 10: Progressive disclosure ---")
    prompt = client2.get_progressive_disclosure_prompt()
    print(f"  Disclosure prompt preview: {prompt[:100]}...")
    assert len(prompt) > 0, "Should have disclosure prompt"
    print("  [PASS] Progressive disclosure works")

    # Test 11: Close investigation
    print("\n--- Test 11: Close investigation ---")
    client2.close_investigation(resolution="Test completed successfully")
    loaded_closed = client2.load_investigation(inv_id)
    from src.storage.models import InvestigationStatus

    assert loaded_closed.manifest.status == InvestigationStatus.CLOSED
    print("  Investigation closed")
    print("  [PASS] Close investigation works")

    # Test 12: Storage stats
    print("\n--- Test 12: Storage stats ---")
    stats = client2.get_storage_stats()
    print(f"  Usage: {stats['current_usage_bytes']} bytes")
    print(f"  Max: {stats['max_size_bytes']} bytes ({stats['max_size_gb']} GB)")
    assert stats["max_size_bytes"] == 8 * 1024 * 1024 * 1024, "Should be 8GB"
    print("  [PASS] Storage stats works")

    print("\n" + "=" * 50)
    print("ALL MCP INVESTIGATION STATE TOOL TESTS PASSED!")
    print("=" * 50)


def cleanup(config):
    """Clean up test data."""
    if config.base_path.exists():
        shutil.rmtree(config.base_path)


if __name__ == "__main__":
    config = setup_test_environment()
    try:
        test_investigation_state_tools()
    finally:
        # Optionally cleanup
        # cleanup(config)
        pass
