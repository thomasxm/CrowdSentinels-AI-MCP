"""Test Live Elasticsearch Integration with Investigation State Storage.

This test runs actual hunts against the Elasticsearch cluster to verify
that IoCs are automatically captured to investigations.
"""

import os
import sys
import shutil
from pathlib import Path

# Configure Elasticsearch connection (HTTP, not HTTPS)
os.environ.setdefault("ELASTICSEARCH_HOSTS", "http://localhost:9200")
os.environ.setdefault("ELASTICSEARCH_USERNAME", "elastic")
os.environ.setdefault("ELASTICSEARCH_PASSWORD", "vJqz2wDD")
os.environ.setdefault("VERIFY_CERTS", "false")

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.storage.config import StorageConfig, set_config


def setup_test_environment():
    """Set up test environment with clean storage."""
    test_path = Path("/tmp/crowdsentinel-live-test")
    if test_path.exists():
        shutil.rmtree(test_path)

    config = StorageConfig(base_path=test_path)
    set_config(config)
    config.ensure_directories()
    return config


def test_live_elasticsearch_hunting():
    """Test live Elasticsearch hunting with auto-capture."""
    print("\n" + "=" * 70)
    print("LIVE ELASTICSEARCH INTEGRATION TEST")
    print("=" * 70)

    # Set up clean environment
    setup_test_environment()

    # Import after setting config
    from src.storage.models import Severity, SourceType
    from src.storage.auto_capture import (
        auto_capture_elasticsearch_results,
        has_active_investigation,
        get_active_investigation_summary,
        get_client,
    )
    from src.clients import create_search_client

    # Reset global client
    import src.storage.auto_capture as auto_module
    auto_module._client = None

    # Initialize Elasticsearch client
    print("\n--- Connecting to Elasticsearch ---")
    es_client = create_search_client("elasticsearch")
    print("  Connected to Elasticsearch cluster")

    # Step 1: Create investigation
    print("\n--- Step 1: Create Investigation ---")
    client = get_client()
    investigation = client.create_investigation(
        name="Live ES Hunt Test",
        description="Testing live Elasticsearch hunting with auto-capture",
        tags=["live-test", "winlogbeat"],
        severity=Severity.MEDIUM,
    )
    print(f"  Created investigation: {investigation.manifest.id}")
    assert has_active_investigation()

    # Step 2: Run a live hunt using search_with_lucene
    print("\n--- Step 2: Run Lucene Search (Logon Events) ---")
    lucene_results = es_client.search_with_lucene(
        index=".ds-winlogbeat-*",
        lucene_query="event.code:(4624 OR 4625 OR 4648)",  # Logon events
        timeframe_minutes=None,  # Search all time
        size=20
    )

    total_hits = lucene_results.get("total_hits", 0)
    print(f"  Found {total_hits} logon events")

    # Auto-capture the results
    captured_lucene = auto_capture_elasticsearch_results(
        results=lucene_results,
        tool_name="search_with_lucene",
        query_description="Windows Logon Events (4624, 4625, 4648)",
        extract_timeline=True,
    )

    capture_info = captured_lucene.get("capture_info", {})
    print(f"  Captured: {capture_info.get('captured')}")
    print(f"  IoCs added: {capture_info.get('iocs_added', 0)}")
    print(f"  Total IoCs: {capture_info.get('total_iocs', 0)}")

    # Step 3: Run hunt_by_timeframe for suspicious processes
    print("\n--- Step 3: Hunt for Suspicious Processes ---")
    hunt_results = es_client.hunt_by_timeframe(
        index=".ds-winlogbeat-*",
        attack_types=["suspicious_process", "encoded_commands"],
        start_time="now-30d",
        host=None
    )

    print(f"  Hunt results:")
    for attack_type, data in hunt_results.get("findings", {}).items():
        hits = data.get("total_hits", 0)
        if hits > 0:
            print(f"    - {attack_type}: {hits} hits")

    # Auto-capture hunt results
    captured_hunt = auto_capture_elasticsearch_results(
        results=hunt_results,
        tool_name="hunt_by_timeframe",
        query_description="Hunt for suspicious processes and encoded commands",
    )

    capture_info2 = captured_hunt.get("capture_info", {})
    print(f"  Additional IoCs added: {capture_info2.get('iocs_added', 0)}")
    print(f"  Total IoCs now: {capture_info2.get('total_iocs', 0)}")

    # Step 4: Hunt for IoC (specific process)
    print("\n--- Step 4: Hunt for Specific IoC (powershell.exe) ---")
    ioc_results = es_client.hunt_for_ioc(
        index=".ds-winlogbeat-*",
        ioc="powershell",
        ioc_type="process",
        timeframe_minutes=None  # All time
    )

    ioc_hits = ioc_results.get("total_hits", 0)
    print(f"  Found {ioc_hits} events involving PowerShell")

    # Auto-capture
    captured_ioc = auto_capture_elasticsearch_results(
        results=ioc_results,
        tool_name="hunt_for_ioc",
        query_description="Hunt for PowerShell activity",
    )

    capture_info3 = captured_ioc.get("capture_info", {})
    print(f"  Additional IoCs added: {capture_info3.get('iocs_added', 0)}")
    print(f"  Total IoCs now: {capture_info3.get('total_iocs', 0)}")

    # Step 5: Get investigation summary
    print("\n--- Step 5: Investigation Summary ---")
    summary = get_active_investigation_summary()
    print(f"  Investigation ID: {summary['id']}")
    print(f"  Name: {summary['name']}")
    print(f"  Total IoCs: {summary['iocs_count']}")
    print(f"  Sources used: {summary['sources_used']}")

    # Step 6: Get shared IoCs
    print("\n--- Step 6: Retrieved Shared IoCs ---")
    shared_iocs = client.get_shared_iocs(min_priority=1, limit=20)
    print(f"  Total shared IoCs: {len(shared_iocs)}")

    # Group by type
    ioc_by_type = {}
    for ioc in shared_iocs:
        ioc_type = ioc.type.value
        if ioc_type not in ioc_by_type:
            ioc_by_type[ioc_type] = []
        ioc_by_type[ioc_type].append(ioc)

    print("\n  IoCs by type:")
    for ioc_type, iocs in sorted(ioc_by_type.items()):
        print(f"    {ioc_type}: {len(iocs)}")
        # Show first 3 of each type
        for ioc in iocs[:3]:
            print(f"      - {ioc.value[:60]}{'...' if len(ioc.value) > 60 else ''}")

    # Step 7: Save and verify persistence
    print("\n--- Step 7: Save and Verify Persistence ---")
    inv_id = investigation.manifest.id
    client.save_state()

    # Reset client
    auto_module._client = None
    new_client = get_client()

    # Resume
    resumed = new_client.resume_investigation(inv_id)
    assert resumed is not None
    assert resumed.iocs.total_count > 0
    print(f"  Resumed investigation with {resumed.iocs.total_count} IoCs")
    print("  [PASS] Persistence verified")

    # Step 8: Export IoCs
    print("\n--- Step 8: Export IoCs for Threat Intel ---")
    exported = new_client.export_iocs(format="json")
    print(f"  Exported {exported.get('total_iocs', 0)} IoCs")

    # Show some high-priority IoCs
    high_priority = [ioc for ioc in shared_iocs if ioc.pyramid_priority >= 4]
    if high_priority:
        print(f"\n  High-priority IoCs (Pyramid level 4+):")
        for ioc in high_priority[:5]:
            print(f"    [{ioc.pyramid_priority}] {ioc.type.value}: {ioc.value[:50]}")

    print("\n" + "=" * 70)
    print("LIVE ELASTICSEARCH INTEGRATION TEST PASSED!")
    print("=" * 70)

    # Final summary
    print(f"""
=== Final Summary ===
Investigation: {inv_id}
Total IoCs collected from live ES data: {resumed.iocs.total_count}
Sources: {resumed.manifest.sources_used}

IoC breakdown:""")
    for ioc_type, count in resumed.iocs.by_type.items():
        print(f"  - {ioc_type}: {count}")

    return True


if __name__ == "__main__":
    success = test_live_elasticsearch_hunting()
    sys.exit(0 if success else 1)
