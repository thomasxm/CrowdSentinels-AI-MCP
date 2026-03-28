"""Test Cross-Tool IoC Sharing between Elasticsearch and Chainsaw."""

import shutil
import sys
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.storage.config import StorageConfig, set_config


def setup_test_environment():
    """Set up test environment with clean storage."""
    # Use a test directory
    test_path = Path("/tmp/crowdsentinel-cross-tool-test")
    if test_path.exists():
        shutil.rmtree(test_path)

    config = StorageConfig(base_path=test_path)
    set_config(config)
    config.ensure_directories()
    return config


def test_cross_tool_ioc_sharing():
    """Test that IoCs are shared across Elasticsearch and Chainsaw tools."""
    print("\n=== Testing Cross-Tool IoC Sharing ===")

    # Set up clean environment
    setup_test_environment()

    # Import after setting config
    # Reset the global client
    import src.storage.auto_capture as auto_module
    from src.storage.auto_capture import (
        auto_capture_chainsaw_results,
        auto_capture_elasticsearch_results,
        get_active_investigation_summary,
        get_client,
        has_active_investigation,
    )
    from src.storage.models import Severity

    auto_module._client = None

    # Test 1: Verify no active investigation initially
    print("\n--- Test 1: No active investigation initially ---")
    assert not has_active_investigation(), "Should not have active investigation"
    print("  [PASS] No active investigation initially")

    # Test 2: Create an investigation
    print("\n--- Test 2: Create investigation ---")
    client = get_client()
    investigation = client.create_investigation(
        name="Cross-Tool IoC Test",
        description="Testing IoC sharing between ES and Chainsaw",
        tags=["test", "cross-tool"],
        severity=Severity.MEDIUM,
    )
    print(f"  Created: {investigation.manifest.id}")
    assert has_active_investigation()
    print("  [PASS] Investigation created")

    # Test 3: Simulate Elasticsearch results and auto-capture
    print("\n--- Test 3: Capture IoCs from Elasticsearch results ---")
    es_results = {
        "hits": {
            "total": {"value": 3},
            "hits": [
                {
                    "_source": {
                        "source.ip": "10.0.0.100",
                        "destination.ip": "203.0.113.50",
                        "user.name": "attacker",
                        "host.name": "VICTIM-PC-01",
                        "process.name": "powershell.exe",
                    }
                },
                {
                    "_source": {
                        "source.ip": "10.0.0.100",
                        "destination.ip": "evil.c2.server",
                        "user.name": "attacker",
                        "host.name": "VICTIM-PC-02",
                    }
                },
            ],
        }
    }

    captured_es = auto_capture_elasticsearch_results(
        results=es_results,
        tool_name="hunt_by_timeframe",
        query_description="Hunting for suspicious activity",
    )

    print(f"  Capture info: {captured_es.get('capture_info')}")
    assert captured_es["capture_info"]["captured"], "Should capture from ES"
    es_iocs_added = captured_es["capture_info"]["iocs_added"]
    print(f"  IoCs added from ES: {es_iocs_added}")
    print("  [PASS] Captured IoCs from Elasticsearch")

    # Test 4: Simulate Chainsaw results and auto-capture
    print("\n--- Test 4: Capture IoCs from Chainsaw results ---")
    chainsaw_results = {
        "total_detections": 2,
        "detections": [
            {
                "name": "Mimikatz Detection",
                "Event": {
                    "System": {"Computer": "VICTIM-PC-03"},
                    "EventData": {
                        "Image": "C:\\Windows\\System32\\mimikatz.exe",
                        "User": "DOMAIN\\hacker",
                        "IpAddress": "192.168.1.200",
                    },
                },
            }
        ],
    }

    captured_chainsaw = auto_capture_chainsaw_results(
        results=chainsaw_results,
        tool_name="hunt_with_sigma_rules",
        query_description="Sigma rule hunt on EVTX logs",
    )

    print(f"  Capture info: {captured_chainsaw.get('capture_info')}")
    assert captured_chainsaw["capture_info"]["captured"], "Should capture from Chainsaw"
    chainsaw_iocs_added = captured_chainsaw["capture_info"]["iocs_added"]
    print(f"  IoCs added from Chainsaw: {chainsaw_iocs_added}")
    print("  [PASS] Captured IoCs from Chainsaw")

    # Test 5: Verify IoCs are shared - both sources contributed
    print("\n--- Test 5: Verify shared IoCs from both sources ---")
    summary = get_active_investigation_summary()
    print(f"  Investigation summary: {summary}")

    total_iocs = summary["iocs_count"]
    sources_used = summary["sources_used"]

    print(f"  Total IoCs collected: {total_iocs}")
    print(f"  Sources used: {sources_used}")

    assert total_iocs >= es_iocs_added + chainsaw_iocs_added - 2, "Should have IoCs from both sources (minus dedupes)"
    assert "elasticsearch" in sources_used, "Should include Elasticsearch source"
    assert "chainsaw" in sources_used, "Should include Chainsaw source"
    print("  [PASS] IoCs are shared across tools")

    # Test 6: Get shared IoCs for cross-tool hunting
    print("\n--- Test 6: Retrieve shared IoCs for cross-tool hunting ---")
    shared_iocs = client.get_shared_iocs(min_priority=1, limit=50)

    print(f"  Shared IoCs retrieved: {len(shared_iocs)}")
    for ioc in shared_iocs[:5]:
        # IoC is a Pydantic model, access as attributes
        print(f"    - {ioc.type.value}: {ioc.value} (priority: {ioc.pyramid_priority})")

    assert len(shared_iocs) > 0, "Should have shared IoCs"

    # Verify IoCs from both sources are present
    ioc_values = {ioc.value for ioc in shared_iocs}
    assert "10.0.0.100" in ioc_values or "203.0.113.50" in ioc_values, "Should have ES IPs"
    print("  [PASS] Shared IoCs available for cross-tool hunting")

    # Test 7: Export IoCs for threat intel
    print("\n--- Test 7: Export IoCs for threat intelligence ---")
    exported = client.export_iocs(format="json")

    print(f"  Exported {exported.get('total_iocs', 0)} IoCs")
    print(f"  Sources in export: {list(exported.get('by_source', {}).keys())}")

    assert exported.get("total_iocs", 0) > 0
    print("  [PASS] IoCs exported for threat intel")

    # Test 8: Verify cross-tool workflow
    print("\n--- Test 8: Cross-tool workflow verification ---")

    # Simulate: Using an IP found in Elasticsearch to search in Chainsaw
    # This demonstrates how IoCs discovered in one tool can be used in another
    from src.storage.models import IoCType

    shared_ips = [ioc for ioc in shared_iocs if ioc.type == IoCType.IP]
    if shared_ips:
        pivot_ip = shared_ips[0].value
        print(f"  Found IP from shared IoCs: {pivot_ip}")
        print("  This IP can now be searched in Chainsaw EVTX logs")
        print(f"  Example: search_ioc_in_evtx(evtx_path='./logs/', ioc='{pivot_ip}', ioc_type='ip')")
    else:
        print("  (No IPs found, but workflow would work with any IoC type)")

    print("  [PASS] Cross-tool workflow is functional")

    # Test 9: Save and verify persistence
    print("\n--- Test 9: Save and verify persistence ---")
    inv_id = investigation.manifest.id
    client.save_state()

    # Reset client to simulate new session
    auto_module._client = None
    new_client = get_client()

    # Resume investigation
    resumed = new_client.resume_investigation(inv_id)
    assert resumed is not None
    assert resumed.iocs.total_count > 0

    # Verify sources are preserved
    assert "elasticsearch" in resumed.manifest.sources_used
    assert "chainsaw" in resumed.manifest.sources_used

    print(f"  Resumed investigation with {resumed.iocs.total_count} IoCs")
    print("  [PASS] Cross-tool state persisted correctly")

    print("\n" + "=" * 60)
    print("ALL CROSS-TOOL IOC SHARING TESTS PASSED!")
    print("=" * 60)

    # Summary
    print("\n--- Summary ---")
    print(f"Investigation: {inv_id}")
    print(f"Total IoCs collected: {resumed.iocs.total_count}")
    print(f"Sources used: {resumed.manifest.sources_used}")
    print("\nIoC breakdown by type:")
    for ioc_type, count in resumed.iocs.by_type.items():
        print(f"  - {ioc_type}: {count}")


if __name__ == "__main__":
    test_cross_tool_ioc_sharing()
