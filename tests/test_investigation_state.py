"""Test investigation state storage functionality."""

import shutil
import sys
from pathlib import Path

import pytest

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.storage.config import StorageConfig, set_config
from src.storage.investigation_state import InvestigationStateClient
from src.storage.models import (
    InvestigationStatus,
    IoC,
    IoCSource,
    IoCType,
    Severity,
    SourceType,
)
from src.storage.smart_extractor import SmartExtractor
from src.storage.storage_manager import StorageManager


@pytest.fixture
def config():
    """Pytest fixture providing StorageConfig for tests."""
    test_path = Path("/tmp/crowdsentinel-test-pytest")
    if test_path.exists():
        shutil.rmtree(test_path)

    cfg = StorageConfig(base_path=test_path)
    set_config(cfg)
    cfg.ensure_directories()

    yield cfg

    # Cleanup after test
    if test_path.exists():
        shutil.rmtree(test_path)


def test_storage_config():
    """Test storage configuration."""
    print("\n=== Testing Storage Configuration ===")

    # Use a test directory
    test_path = Path("/tmp/crowdsentinel-test")
    if test_path.exists():
        shutil.rmtree(test_path)

    config = StorageConfig(base_path=test_path)
    set_config(config)

    config.ensure_directories()

    assert test_path.exists(), "Base path should exist"
    assert config.investigations_path.exists(), "Investigations path should exist"
    assert config.max_size_bytes == 8 * 1024 * 1024 * 1024, "Max size should be 8GB"

    print(f"  Storage path: {config.base_path}")
    print(f"  Max size: {config.storage.max_size_gb} GB")
    print("  [PASS] Storage configuration works")

    return config


def test_storage_manager(config: StorageConfig):
    """Test storage manager."""
    print("\n=== Testing Storage Manager ===")

    manager = StorageManager(config)

    # Check initial state
    usage = manager.calculate_usage()
    print(f"  Initial usage: {usage} bytes")

    # Create a test investigation directory
    inv_id = "INV-TEST-001"
    inv_path = manager.create_investigation_dir(inv_id)

    assert inv_path.exists(), "Investigation dir should exist"
    assert (inv_path / "iocs").exists(), "IoCs subdir should exist"
    assert (inv_path / "timeline").exists(), "Timeline subdir should exist"

    # Write some test data
    (inv_path / "manifest.json").write_text('{"test": true}')

    # Check size
    size = manager.get_investigation_size(inv_id)
    print(f"  Investigation size: {size} bytes")
    assert size > 0, "Size should be > 0"

    # Clean up
    manager.delete_investigation(inv_id)
    assert not inv_path.exists(), "Investigation should be deleted"

    print("  [PASS] Storage manager works")

    return manager


def test_smart_extractor():
    """Test smart extractor."""
    print("\n=== Testing Smart Extractor ===")

    extractor = SmartExtractor()

    # Simulate Elasticsearch results
    es_results = {
        "hits": {
            "total": {"value": 3},
            "hits": [
                {
                    "_source": {
                        "source.ip": "192.168.1.100",
                        "destination.ip": "10.0.0.50",
                        "user.name": "jsmith",
                        "host.name": "WS-FINANCE-01",
                        "process.name": "powershell.exe",
                        "process.command_line": "powershell.exe -enc SGVsbG8gV29ybGQ=",
                        "event.code": "4688",
                        "@timestamp": "2024-12-28T10:00:00Z",
                    }
                },
                {
                    "_source": {
                        "source.ip": "192.168.1.100",
                        "user.name": "jsmith",
                        "host.name": "WS-FINANCE-01",
                        "event.code": "4624",
                        "@timestamp": "2024-12-28T09:55:00Z",
                    }
                },
                {
                    "_source": {
                        "source.ip": "192.168.1.101",
                        "user.name": "admin",
                        "host.name": "DC-01",
                        "event.code": "4672",
                        "@timestamp": "2024-12-28T10:05:00Z",
                    }
                },
            ],
        }
    }

    # Extract IoCs
    iocs = extractor.extract_iocs_from_elasticsearch(
        es_results,
        source_tool="hunt_by_timeframe",
        investigation_id="INV-TEST-001",
    )

    print(f"  Extracted {len(iocs)} IoCs")
    assert len(iocs) > 0, "Should extract some IoCs"

    # Check IoC types
    types = set(ioc.type for ioc in iocs)
    print(f"  IoC types: {[t.value for t in types]}")
    assert IoCType.IP in types, "Should extract IPs"
    assert IoCType.USER in types, "Should extract users"
    assert IoCType.HOSTNAME in types, "Should extract hostnames"

    # Check deduplication (192.168.1.100 appears twice)
    ip_iocs = [i for i in iocs if i.type == IoCType.IP and i.value == "192.168.1.100"]
    if ip_iocs:
        print(f"  IP 192.168.1.100 occurrences: {ip_iocs[0].total_occurrences}")

    # Check priority sorting
    priorities = [ioc.pyramid_priority for ioc in iocs[:5]]
    print(f"  Top 5 priorities: {priorities}")
    assert priorities == sorted(priorities, reverse=True), "Should be sorted by priority"

    # Test summarize events
    events = [h["_source"] for h in es_results["hits"]["hits"]]
    findings = extractor.summarize_events(events, SourceType.ELASTICSEARCH, "test")

    print(f"  Summary: {findings.total_events} events, {len(findings.key_findings)} findings")
    assert findings.total_events == 3, "Should have 3 events"

    print("  [PASS] Smart extractor works")

    return extractor


def test_investigation_state_client(config: StorageConfig):
    """Test investigation state client."""
    print("\n=== Testing Investigation State Client ===")

    client = InvestigationStateClient(config)

    # Create investigation
    investigation = client.create_investigation(
        name="Test Ransomware Investigation",
        description="Testing investigation state storage",
        tags=["test", "ransomware"],
        severity=Severity.HIGH,
    )

    print(f"  Created: {investigation.manifest.id}")
    assert investigation.manifest.id.startswith("INV-"), "ID should start with INV-"
    assert client.active_investigation_id == investigation.manifest.id

    # Add IoCs manually
    ioc1 = IoC(
        type=IoCType.IP,
        value="203.0.113.42",
        pyramid_priority=2,
        sources=[IoCSource(tool="manual", source_type=SourceType.MANUAL)],
        tags=["c2", "malicious"],
    )
    ioc2 = IoC(
        type=IoCType.PROCESS,
        value="malware.exe",
        pyramid_priority=5,
        sources=[IoCSource(tool="manual", source_type=SourceType.MANUAL)],
    )

    added = client.add_iocs([ioc1, ioc2])
    print(f"  Added {added} IoCs")
    assert added == 2, "Should add 2 IoCs"

    # Add the same IoC again (should merge)
    ioc1_dup = IoC(
        type=IoCType.IP,
        value="203.0.113.42",
        pyramid_priority=2,
        sources=[IoCSource(tool="chainsaw", source_type=SourceType.CHAINSAW)],
    )
    added2 = client.add_iocs([ioc1_dup])
    print(f"  Added {added2} IoCs (duplicate)")
    assert added2 == 0, "Duplicate should merge, not add"

    # Check the merged IoC
    merged_ioc = next((i for i in investigation.iocs.iocs if i.value == "203.0.113.42"), None)
    assert merged_ioc is not None
    assert len(merged_ioc.sources) == 2, "Should have 2 sources after merge"
    print(f"  Merged IoC sources: {[s.tool for s in merged_ioc.sources]}")

    # Add findings from simulated ES results
    es_results = {
        "hits": {
            "total": {"value": 5},
            "hits": [
                {"_source": {"source.ip": "192.168.1.50", "user.name": "testuser", "event.code": "4688"}},
                {"_source": {"source.ip": "192.168.1.51", "host.name": "SERVER-01", "event.code": "4624"}},
            ],
        }
    }

    summary = client.add_findings(
        source_type=SourceType.ELASTICSEARCH,
        source_tool="hunt_by_timeframe",
        results=es_results,
        query_description="Test hunt query",
    )

    print(f"  Findings: {summary}")
    assert summary["iocs_added"] > 0, "Should add IoCs from findings"

    # Get summary
    text_summary = client.get_summary(format="compact")
    print(f"  Summary:\n{text_summary}")
    assert investigation.manifest.id in text_summary

    # Save and reload
    client.save_state()

    # Load in a new client (simulating new session)
    client2 = InvestigationStateClient(config)
    loaded = client2.load_investigation(investigation.manifest.id)

    assert loaded is not None, "Should load investigation"
    assert loaded.manifest.name == investigation.manifest.name
    assert loaded.iocs.total_count == investigation.iocs.total_count
    print(f"  Reloaded: {loaded.iocs.total_count} IoCs")

    # Test progressive disclosure
    prompt = client2.get_progressive_disclosure_prompt()
    print(f"  Progressive disclosure:\n{prompt[:200]}...")
    assert "active investigations" in prompt.lower() or investigation.manifest.id in prompt

    # Test shared IoCs
    shared = client2.get_shared_iocs(min_priority=2, limit=10)
    print(f"  Shared IoCs: {len(shared)}")
    assert len(shared) > 0, "Should have shared IoCs"

    # Resume to make it active before export
    client2.resume_investigation(investigation.manifest.id)

    # Export IoCs
    exported = client2.export_iocs(format="json")
    print(f"  Exported {exported['total_iocs']} IoCs")

    # Close investigation
    client2.close_investigation(resolution="Test completed")

    # Verify closed
    closed = client2.load_investigation(investigation.manifest.id)
    assert closed.manifest.status == InvestigationStatus.CLOSED
    print("  Investigation closed")

    # Storage stats
    stats = client2.get_storage_stats()
    print(f"  Storage: {stats['current_usage_bytes']} bytes / {stats['max_size_bytes']} bytes")

    print("  [PASS] Investigation state client works")

    return client


def test_cross_tool_sharing(config: StorageConfig):
    """Test IoC sharing between different tools."""
    print("\n=== Testing Cross-Tool IoC Sharing ===")

    client = InvestigationStateClient(config)

    # Create investigation
    investigation = client.create_investigation(
        name="Cross-Tool Test",
        description="Testing IoC sharing between ES and Chainsaw",
        severity=Severity.MEDIUM,
    )

    # Simulate Elasticsearch finding an IP
    es_results = {
        "hits": {
            "total": {"value": 10},
            "hits": [
                {"_source": {"source.ip": "10.20.30.40", "user.name": "attacker", "event.code": "4625"}},
                {"_source": {"source.ip": "10.20.30.40", "user.name": "attacker", "event.code": "4625"}},
                {"_source": {"source.ip": "10.20.30.40", "host.name": "DC-MAIN", "event.code": "4625"}},
            ],
        }
    }

    client.add_findings(
        source_type=SourceType.ELASTICSEARCH,
        source_tool="analyze_failed_logins",
        results=es_results,
        query_description="Brute force detection",
    )

    print(f"  Added ES findings: {investigation.iocs.total_count} IoCs")

    # Simulate Chainsaw finding the same IP + new ones
    chainsaw_results = {
        "detections": [
            {
                "rule": {"name": "Suspicious Login"},
                "event": {"source.ip": "10.20.30.40", "user.name": "attacker"},
            },
            {
                "rule": {"name": "Mimikatz Detection"},
                "event": {"process.name": "mimikatz.exe", "host.name": "DC-MAIN"},
            },
        ]
    }

    client.add_findings(
        source_type=SourceType.CHAINSAW,
        source_tool="hunt_with_sigma_rules",
        results=chainsaw_results,
        query_description="Sigma rule hunt",
    )

    print(f"  After Chainsaw: {investigation.iocs.total_count} IoCs")

    # Check the shared IP
    ip_ioc = next((i for i in investigation.iocs.iocs if i.type == IoCType.IP and i.value == "10.20.30.40"), None)

    assert ip_ioc is not None, "Should have the IP"
    print(f"  IP 10.20.30.40 sources: {[s.tool for s in ip_ioc.sources]}")

    # Verify sources
    source_tools = [s.tool for s in ip_ioc.sources]
    assert "analyze_failed_logins" in source_tools, "Should have ES source"
    assert "hunt_with_sigma_rules" in source_tools, "Should have Chainsaw source"

    print(f"  IP occurrences: {ip_ioc.total_occurrences}")
    assert ip_ioc.total_occurrences >= 3, "Should have multiple occurrences"

    # Check sources used in manifest
    print(f"  Sources used: {investigation.manifest.sources_used}")
    assert "elasticsearch" in investigation.manifest.sources_used
    assert "chainsaw" in investigation.manifest.sources_used

    # Simulate a new session wanting to use shared IoCs
    client2 = InvestigationStateClient(config)

    # Get shared IoCs that both tools found
    shared = client2.get_shared_iocs(min_priority=2)
    print(f"  Shared IoCs (priority >= 2): {len(shared)}")

    # Filter to IPs that both tools saw
    multi_source_iocs = [i for i in shared if len(set(s.source_type for s in i.sources)) > 1]
    print(f"  Multi-source IoCs: {len(multi_source_iocs)}")

    # Export for use in another tool
    exported = client.export_iocs(format="values", ioc_types=[IoCType.IP])
    print(f"  Exported IPs:\n{exported}")

    print("  [PASS] Cross-tool IoC sharing works")

    # Cleanup
    client.close_investigation(resolution="Test completed")


def cleanup(config: StorageConfig):
    """Clean up test data."""
    print("\n=== Cleanup ===")
    if config.base_path.exists():
        shutil.rmtree(config.base_path)
        print(f"  Removed {config.base_path}")


def main():
    """Run all tests."""
    print("=" * 60)
    print("Investigation State Storage Tests")
    print("=" * 60)

    try:
        config = test_storage_config()
        test_storage_manager(config)
        test_smart_extractor()
        test_investigation_state_client(config)
        test_cross_tool_sharing(config)

        print("\n" + "=" * 60)
        print("ALL TESTS PASSED!")
        print("=" * 60)

    except AssertionError as e:
        print(f"\n[FAIL] Test failed: {e}")
        raise
    except Exception as e:
        print(f"\n[ERROR] Unexpected error: {e}")
        raise
    finally:
        # Optionally cleanup
        # cleanup(config)
        pass


if __name__ == "__main__":
    main()
