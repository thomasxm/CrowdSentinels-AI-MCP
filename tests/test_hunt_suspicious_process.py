"""Test hunt_suspicious_process_activity tool for IoC extraction."""

import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.tools.esql_hunting import ESQLHuntingTools


def create_mock_esql_client():
    """Create a mock ESQLClient for testing."""
    mock_client = MagicMock()
    mock_client.es_version = "8.15.0"
    return mock_client


def create_mock_hunting_loader():
    """Create a mock HuntingRuleLoader for testing."""
    return MagicMock()


def create_stage1_response(
    start_time: str = "2024-01-15T10:00:00.000Z",
    end_time: str = "2024-01-15T10:30:00.000Z",
    hosts: list = None,
    users: list = None,
    executables: list = None,
    parent_processes: list = None
) -> dict[str, Any]:
    """Create a mock Stage 1 (process bounds) response."""
    return {
        "hits_count": 1,
        "results": [{
            "start_time": start_time,
            "end_time": end_time,
            "hosts": hosts or ["VICTIM-PC"],
            "users": users or ["admin"],
            "executables": executables or ["C:\\malware\\maze.exe"],
            "parent_processes": parent_processes or ["explorer.exe"]
        }]
    }


def create_stage2_response(child_processes: list = None) -> dict[str, Any]:
    """Create a mock Stage 2 (child processes) response."""
    if child_processes is None:
        child_processes = [
            {
                "@timestamp": "2024-01-15T10:05:00.000Z",
                "event.action": "Process Create",
                "process.name": "cmd.exe",
                "process.executable": "C:\\Windows\\System32\\cmd.exe",
                "process.command_line": "cmd.exe /c whoami",
                "user.name": "admin"
            },
            {
                "@timestamp": "2024-01-15T10:10:00.000Z",
                "event.action": "Process Create",
                "process.name": "powershell.exe",
                "process.executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "process.command_line": "powershell -enc SGVsbG8gV29ybGQ=",
                "user.name": "admin"
            },
            {
                "@timestamp": "2024-01-15T10:15:00.000Z",
                "event.action": "Process Create",
                "process.name": "vssadmin.exe",
                "process.executable": "C:\\Windows\\System32\\vssadmin.exe",
                "process.command_line": "vssadmin delete shadows /all /quiet",
                "user.name": "SYSTEM"
            }
        ]
    return {
        "hits_count": len(child_processes),
        "results": child_processes
    }


def create_stage3_response(file_operations: list = None) -> dict[str, Any]:
    """Create a mock Stage 3 (file operations) response."""
    if file_operations is None:
        file_operations = [
            {
                "@timestamp": "2024-01-15T10:06:00.000Z",
                "event.action": "creation",
                "file.path": "C:\\Users\\admin\\Desktop\\DECRYPT-FILES.txt",
                "file.name": "DECRYPT-FILES.txt",
                "file.extension": "txt",
                "process.name": "maze.exe"
            },
            {
                "@timestamp": "2024-01-15T10:07:00.000Z",
                "event.action": "modification",
                "file.path": "C:\\Users\\admin\\Documents\\important.docx.encrypted",
                "file.name": "important.docx.encrypted",
                "file.extension": "encrypted",
                "process.name": "maze.exe"
            },
            {
                "@timestamp": "2024-01-15T10:08:00.000Z",
                "event.action": "creation",
                "file.path": "C:\\Windows\\Temp\\payload.dll",
                "file.name": "payload.dll",
                "file.extension": "dll",
                "process.name": "maze.exe"
            }
        ]
    return {
        "hits_count": len(file_operations),
        "results": file_operations
    }


def create_stage4_response(network_connections: list = None) -> dict[str, Any]:
    """Create a mock Stage 4 (network connections) response."""
    if network_connections is None:
        network_connections = [
            {
                "@timestamp": "2024-01-15T10:02:00.000Z",
                "event.action": "connection_attempted",
                "process.name": "maze.exe",
                "destination.ip": "185.220.101.42",
                "destination.port": 443,
                "network.protocol": "tcp"
            },
            {
                "@timestamp": "2024-01-15T10:12:00.000Z",
                "event.action": "connection_attempted",
                "process.name": "maze.exe",
                "destination.ip": "91.219.236.222",
                "destination.port": 8080,
                "network.protocol": "tcp"
            },
            {
                "@timestamp": "2024-01-15T10:20:00.000Z",
                "event.action": "connection_attempted",
                "process.name": "powershell.exe",
                "destination.ip": "185.220.101.42",
                "destination.port": 443,
                "network.protocol": "tcp"
            }
        ]
    return {
        "hits_count": len(network_connections),
        "results": network_connections
    }


class TestHuntSuspiciousProcessActivity:
    """Test suite for hunt_suspicious_process_activity tool."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_esql_client = create_mock_esql_client()
        self.mock_hunting_loader = create_mock_hunting_loader()
        self.tools = ESQLHuntingTools(self.mock_hunting_loader, self.mock_esql_client)

        # Create a mock FastMCP to register tools
        self.mock_mcp = MagicMock()
        self.registered_tools = {}

        def capture_tool(func):
            self.registered_tools[func.__name__] = func
            return func

        self.mock_mcp.tool.return_value = capture_tool
        self.tools.register_tools(self.mock_mcp)

    def test_extracts_iocs_from_all_stages(self):
        """Test that IoCs are extracted from all 4 stages."""
        print("\n=== Testing IoC Extraction from All Stages ===")

        # Set up mock responses for each stage
        call_count = [0]

        def mock_execute(query, lean=False):
            call_count[0] += 1
            if call_count[0] == 1:
                return create_stage1_response()
            if call_count[0] == 2:
                return create_stage2_response()
            if call_count[0] == 3:
                return create_stage3_response()
            if call_count[0] == 4:
                return create_stage4_response()
            return {"hits_count": 0, "results": []}

        self.mock_esql_client.execute = mock_execute

        # Execute the hunt (disable new stages to test original 4-stage IoC extraction)
        # Use ECS schema hint since mock data uses ECS field names
        hunt_func = self.registered_tools["hunt_suspicious_process_activity"]
        result = hunt_func(
            process_name="maze.exe",
            schema_hint="ecs",
            include_registry=False,
            include_process_access=False,
            include_remote_threads=False,
            include_dns=False
        )

        # Verify IoCs extracted
        iocs = result["iocs"]

        # Check hostnames from Stage 1
        assert "VICTIM-PC" in iocs["hostnames"], "Should extract hostname from process bounds"
        print(f"  ✓ Hostnames extracted: {iocs['hostnames']}")

        # Check process IoCs from Stage 2 (child processes)
        # Note: IoCs come from child process executables, not the main process
        assert "C:\\Windows\\System32\\cmd.exe" in iocs["processes"], "Should extract child process executable"
        assert "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" in iocs["processes"], "Should extract powershell executable"
        assert "C:\\Windows\\System32\\vssadmin.exe" in iocs["processes"], "Should extract vssadmin executable"
        print(f"  ✓ Processes extracted: {len(iocs['processes'])} unique")

        # Check file IoCs from Stage 3
        assert "C:\\Users\\admin\\Desktop\\DECRYPT-FILES.txt" in iocs["files"], "Should extract ransom note path"
        assert "C:\\Windows\\Temp\\payload.dll" in iocs["files"], "Should extract payload path"
        print(f"  ✓ Files extracted: {len(iocs['files'])} unique")

        # Check IP IoCs from Stage 4
        assert "185.220.101.42" in iocs["ips"], "Should extract C2 IP"
        assert "91.219.236.222" in iocs["ips"], "Should extract second C2 IP"
        print(f"  ✓ IPs extracted: {iocs['ips']}")

        print("  [PASS] All IoC types extracted correctly")

    def test_iocs_are_deduplicated(self):
        """Test that duplicate IoCs are removed."""
        print("\n=== Testing IoC Deduplication ===")

        call_count = [0]

        def mock_execute(query, lean=False):
            call_count[0] += 1
            if call_count[0] == 1:
                return create_stage1_response()
            if call_count[0] == 2:
                # Return duplicate process names
                return create_stage2_response([
                    {"@timestamp": "2024-01-15T10:05:00.000Z", "process.name": "cmd.exe", "process.executable": "C:\\Windows\\System32\\cmd.exe"},
                    {"@timestamp": "2024-01-15T10:06:00.000Z", "process.name": "cmd.exe", "process.executable": "C:\\Windows\\System32\\cmd.exe"},
                    {"@timestamp": "2024-01-15T10:07:00.000Z", "process.name": "cmd.exe", "process.executable": "C:\\Windows\\System32\\cmd.exe"},
                ])
            if call_count[0] == 3:
                return create_stage3_response([])
            if call_count[0] == 4:
                # Return duplicate IPs
                return create_stage4_response([
                    {"@timestamp": "2024-01-15T10:02:00.000Z", "destination.ip": "185.220.101.42"},
                    {"@timestamp": "2024-01-15T10:03:00.000Z", "destination.ip": "185.220.101.42"},
                    {"@timestamp": "2024-01-15T10:04:00.000Z", "destination.ip": "185.220.101.42"},
                ])
            return {"hits_count": 0, "results": []}

        self.mock_esql_client.execute = mock_execute

        hunt_func = self.registered_tools["hunt_suspicious_process_activity"]
        result = hunt_func(
            process_name="maze.exe",
            schema_hint="ecs",
            include_registry=False,
            include_process_access=False,
            include_remote_threads=False,
            include_dns=False
        )

        iocs = result["iocs"]

        # Check deduplication
        assert iocs["ips"].count("185.220.101.42") == 1, "IP should appear only once"
        # Note: IoCs use process.executable (full path), not process.name
        assert iocs["processes"].count("C:\\Windows\\System32\\cmd.exe") == 1, "Process executable should appear only once"

        print(f"  ✓ IPs deduplicated: {iocs['ips']}")
        print(f"  ✓ Processes deduplicated: {iocs['processes']}")
        print("  [PASS] IoCs correctly deduplicated")

    def test_timeline_is_chronologically_sorted(self):
        """Test that timeline events are sorted by timestamp."""
        print("\n=== Testing Timeline Sorting ===")

        call_count = [0]

        def mock_execute(query, lean=False):
            call_count[0] += 1
            if call_count[0] == 1:
                return create_stage1_response()
            if call_count[0] == 2:
                return create_stage2_response([
                    {"@timestamp": "2024-01-15T10:15:00.000Z", "process.name": "late_process.exe"}
                ])
            if call_count[0] == 3:
                return create_stage3_response([
                    {"@timestamp": "2024-01-15T10:05:00.000Z", "file.path": "C:\\early_file.txt"}
                ])
            if call_count[0] == 4:
                return create_stage4_response([
                    {"@timestamp": "2024-01-15T10:10:00.000Z", "destination.ip": "1.2.3.4"}
                ])
            return {"hits_count": 0, "results": []}

        self.mock_esql_client.execute = mock_execute

        hunt_func = self.registered_tools["hunt_suspicious_process_activity"]
        result = hunt_func(
            process_name="maze.exe",
            schema_hint="ecs",
            include_registry=False,
            include_process_access=False,
            include_remote_threads=False,
            include_dns=False
        )

        timeline = result["timeline"]

        # Verify chronological order
        timestamps = [event["timestamp"] for event in timeline]
        assert timestamps == sorted(timestamps), "Timeline should be chronologically sorted"

        # Verify event types are mixed correctly
        assert timeline[0]["type"] == "file_operation", "First event should be file (earliest)"
        assert timeline[1]["type"] == "network_connection", "Second event should be network"
        assert timeline[2]["type"] == "child_process", "Third event should be process (latest)"

        print(f"  ✓ Timeline has {len(timeline)} events")
        print(f"  ✓ Order: {[e['type'] for e in timeline]}")
        print("  [PASS] Timeline correctly sorted")

    def test_summary_statistics(self):
        """Test that summary statistics are calculated correctly."""
        print("\n=== Testing Summary Statistics ===")

        call_count = [0]

        def mock_execute(query, lean=False):
            call_count[0] += 1
            if call_count[0] == 1:
                return create_stage1_response(hosts=["HOST1", "HOST2"])
            if call_count[0] == 2:
                return create_stage2_response()  # 3 child processes
            if call_count[0] == 3:
                return create_stage3_response()  # 3 file operations
            if call_count[0] == 4:
                return create_stage4_response()  # 3 network connections
            return {"hits_count": 0, "results": []}

        self.mock_esql_client.execute = mock_execute

        hunt_func = self.registered_tools["hunt_suspicious_process_activity"]
        result = hunt_func(
            process_name="maze.exe",
            schema_hint="ecs",
            include_registry=False,
            include_process_access=False,
            include_remote_threads=False,
            include_dns=False
        )

        summary = result["summary"]

        assert summary["process_found"] is True
        assert summary["hosts_affected"] == 2
        assert summary["child_processes_count"] == 3
        assert summary["file_operations_count"] == 3
        assert summary["network_connections_count"] == 3
        assert summary["total_timeline_events"] == 9
        assert "T1059" in summary["mitre_techniques"]

        print(f"  ✓ Hosts affected: {summary['hosts_affected']}")
        print(f"  ✓ Child processes: {summary['child_processes_count']}")
        print(f"  ✓ File operations: {summary['file_operations_count']}")
        print(f"  ✓ Network connections: {summary['network_connections_count']}")
        print(f"  ✓ Total IoCs: {summary['total_iocs_extracted']}")
        print("  [PASS] Summary statistics correct")

    def test_process_not_found(self):
        """Test handling when process is not found."""
        print("\n=== Testing Process Not Found ===")

        def mock_execute(query, lean=False):
            return {"hits_count": 0, "results": []}

        self.mock_esql_client.execute = mock_execute

        hunt_func = self.registered_tools["hunt_suspicious_process_activity"]
        # Use ECS schema hint for consistency
        result = hunt_func(
            process_name="nonexistent.exe",
            timeframe_days=30,
            schema_hint="ecs",
            include_registry=False,
            include_process_access=False,
            include_remote_threads=False,
            include_dns=False
        )

        assert result["process_bounds"] is None
        assert result["summary"]["process_found"] is False
        assert len(result["child_processes"]) == 0
        assert len(result["file_operations"]) == 0
        assert len(result["network_connections"]) == 0
        assert "No execution of 'nonexistent.exe'" in result["stages"][0].get("message", "")

        print("  ✓ process_bounds is None")
        print("  ✓ summary.process_found is False")
        print("  ✓ All activity lists are empty")
        print("  [PASS] Handles missing process correctly")

    def test_selective_stages(self):
        """Test that stages can be selectively disabled."""
        print("\n=== Testing Selective Stage Execution ===")

        call_count = [0]
        queries_executed = []

        def mock_execute(query, lean=False):
            call_count[0] += 1
            queries_executed.append(query)
            if call_count[0] == 1:
                return create_stage1_response()
            return {"hits_count": 0, "results": []}

        self.mock_esql_client.execute = mock_execute

        hunt_func = self.registered_tools["hunt_suspicious_process_activity"]

        # Only enable child processes, disable all other stages
        # Use ECS schema hint since mock data uses ECS field names
        result = hunt_func(
            process_name="test.exe",
            schema_hint="ecs",
            include_child_processes=True,
            include_files=False,
            include_network=False,
            include_registry=False,
            include_process_access=False,
            include_remote_threads=False,
            include_dns=False
        )

        # Should only execute 2 queries (Stage 1 + Stage 2)
        assert call_count[0] == 2, f"Expected 2 queries, got {call_count[0]}"
        assert len(result["file_operations"]) == 0
        assert len(result["network_connections"]) == 0

        print(f"  ✓ Queries executed: {call_count[0]}")
        print("  ✓ File operations skipped")
        print("  ✓ Network connections skipped")
        print("  [PASS] Selective stages work correctly")

    def test_error_handling_in_stages(self):
        """Test that errors in individual stages are captured."""
        print("\n=== Testing Error Handling ===")

        call_count = [0]

        def mock_execute(query, lean=False):
            call_count[0] += 1
            if call_count[0] == 1:
                return create_stage1_response()
            if call_count[0] == 2:
                raise Exception("Network timeout on child process query")
            if call_count[0] == 3:
                return create_stage3_response()
            if call_count[0] == 4:
                raise Exception("Index not found for network data")
            return {"hits_count": 0, "results": []}

        self.mock_esql_client.execute = mock_execute

        hunt_func = self.registered_tools["hunt_suspicious_process_activity"]
        # Disable new stages to test original 4-stage error handling
        # Use ECS schema hint since mock data uses ECS field names
        result = hunt_func(
            process_name="test.exe",
            schema_hint="ecs",
            include_registry=False,
            include_process_access=False,
            include_remote_threads=False,
            include_dns=False
        )

        # Should have errors recorded
        assert len(result["errors"]) == 2
        assert "Stage 2" in result["errors"][0]
        assert "Stage 4" in result["errors"][1]

        # File operations should still work (Stage 3)
        assert len(result["file_operations"]) == 3

        # Check stages have error status
        stage_statuses = {s["stage"]: s["status"] for s in result["stages"]}
        assert stage_statuses[1] == "success"
        assert stage_statuses[2] == "error"
        assert stage_statuses[3] == "success"
        assert stage_statuses[4] == "error"

        print(f"  ✓ Errors captured: {len(result['errors'])}")
        print("  ✓ Stage 3 still succeeded despite Stage 2 failure")
        print("  [PASS] Error handling works correctly")

    def test_ioc_extraction_with_ransomware_scenario(self):
        """Integration-style test with realistic ransomware IoCs."""
        print("\n=== Testing Ransomware Scenario IoC Extraction ===")

        call_count = [0]

        def mock_execute(query, lean=False):
            call_count[0] += 1
            if call_count[0] == 1:
                return create_stage1_response(
                    hosts=["FINANCE-PC-01"],
                    users=["john.smith"],
                    executables=["C:\\Users\\john.smith\\Downloads\\invoice.exe"],
                    parent_processes=["outlook.exe"]
                )
            if call_count[0] == 2:
                return create_stage2_response([
                    {"@timestamp": "2024-01-15T10:01:00.000Z", "process.name": "wmic.exe",
                     "process.executable": "C:\\Windows\\System32\\wbem\\WMIC.exe",
                     "process.command_line": "wmic shadowcopy delete"},
                    {"@timestamp": "2024-01-15T10:02:00.000Z", "process.name": "vssadmin.exe",
                     "process.executable": "C:\\Windows\\System32\\vssadmin.exe",
                     "process.command_line": "vssadmin delete shadows /all /quiet"},
                    {"@timestamp": "2024-01-15T10:03:00.000Z", "process.name": "bcdedit.exe",
                     "process.executable": "C:\\Windows\\System32\\bcdedit.exe",
                     "process.command_line": "bcdedit /set {default} recoveryenabled No"},
                ])
            if call_count[0] == 3:
                return create_stage3_response([
                    {"@timestamp": "2024-01-15T10:05:00.000Z", "file.path": "C:\\README_DECRYPT.txt"},
                    {"@timestamp": "2024-01-15T10:06:00.000Z", "file.path": "C:\\Users\\john.smith\\Documents\\Q4_Report.xlsx.encrypted"},
                    {"@timestamp": "2024-01-15T10:07:00.000Z", "file.path": "C:\\Users\\john.smith\\Desktop\\family_photos.zip.encrypted"},
                ])
            if call_count[0] == 4:
                return create_stage4_response([
                    {"@timestamp": "2024-01-15T10:00:30.000Z", "destination.ip": "45.33.32.156", "destination.port": 443},
                    {"@timestamp": "2024-01-15T10:04:00.000Z", "destination.ip": "185.141.62.123", "destination.port": 8443},
                ])
            return {"hits_count": 0, "results": []}

        self.mock_esql_client.execute = mock_execute

        hunt_func = self.registered_tools["hunt_suspicious_process_activity"]
        # Use ECS schema hint since mock data uses ECS field names
        result = hunt_func(
            process_name="invoice.exe",
            timeframe_days=1,
            schema_hint="ecs",
            include_registry=False,
            include_process_access=False,
            include_remote_threads=False,
            include_dns=False
        )

        iocs = result["iocs"]

        # Verify ransomware-specific IoCs
        assert "FINANCE-PC-01" in iocs["hostnames"]
        # Note: IoCs use full executable paths from process.executable
        assert "C:\\Windows\\System32\\wbem\\WMIC.exe" in iocs["processes"]
        assert "C:\\Windows\\System32\\vssadmin.exe" in iocs["processes"]
        assert "C:\\Windows\\System32\\bcdedit.exe" in iocs["processes"]
        assert "C:\\README_DECRYPT.txt" in iocs["files"]
        assert "45.33.32.156" in iocs["ips"]
        assert "185.141.62.123" in iocs["ips"]

        print("  ✓ Victim host: FINANCE-PC-01")
        print("  ✓ Shadow deletion tools detected: WMIC.exe, vssadmin.exe")
        print("  ✓ Recovery disabled: bcdedit.exe")
        print("  ✓ Ransom note: README_DECRYPT.txt")
        print(f"  ✓ C2 IPs: {iocs['ips']}")
        print(f"  ✓ Total IoCs: {result['summary']['total_iocs_extracted']}")
        print("  [PASS] Ransomware IoCs correctly extracted")


def test_hunt_suspicious_process_activity_exists():
    """Verify the tool is registered correctly."""
    print("\n=== Testing Tool Registration ===")

    mock_esql_client = create_mock_esql_client()
    mock_hunting_loader = create_mock_hunting_loader()
    tools = ESQLHuntingTools(mock_hunting_loader, mock_esql_client)

    mock_mcp = MagicMock()
    registered = []

    def capture_tool(func):
        registered.append(func.__name__)
        return func

    mock_mcp.tool.return_value = capture_tool
    tools.register_tools(mock_mcp)

    assert "hunt_suspicious_process_activity" in registered
    print("  ✓ Tool registered: hunt_suspicious_process_activity")
    print(f"  ✓ Total tools registered: {len(registered)}")
    print("  [PASS] Tool registration verified")


if __name__ == "__main__":
    # Run tests
    print("=" * 60)
    print("Testing hunt_suspicious_process_activity IoC Extraction")
    print("=" * 60)

    test_hunt_suspicious_process_activity_exists()

    test_suite = TestHuntSuspiciousProcessActivity()
    test_suite.setup_method()
    test_suite.test_extracts_iocs_from_all_stages()

    test_suite.setup_method()
    test_suite.test_iocs_are_deduplicated()

    test_suite.setup_method()
    test_suite.test_timeline_is_chronologically_sorted()

    test_suite.setup_method()
    test_suite.test_summary_statistics()

    test_suite.setup_method()
    test_suite.test_process_not_found()

    test_suite.setup_method()
    test_suite.test_selective_stages()

    test_suite.setup_method()
    test_suite.test_error_handling_in_stages()

    test_suite.setup_method()
    test_suite.test_ioc_extraction_with_ransomware_scenario()

    print("\n" + "=" * 60)
    print("All tests passed!")
    print("=" * 60)
