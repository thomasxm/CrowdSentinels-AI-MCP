# tests/wireshark/test_lateral_movement.py
"""Tests for lateral movement detector."""
from pathlib import Path

import pytest

TEST_PCAP_DIR = Path("/home/kali/Desktop/CTU/normal_traffics")


class TestLateralMovementDetector:
    """Test lateral movement detection."""

    def test_detect_smb_internal_to_internal(self):
        """Should detect SMB connections between internal hosts."""
        from src.wireshark.hunting.lateral_movement import LateralMovementDetector

        detector = LateralMovementDetector()

        connections = [
            {"src_ip": "192.168.1.100", "dst_ip": "192.168.1.50", "dst_port": 445,
             "protocol": "tcp", "timestamp": 1704067200.0},
            {"src_ip": "192.168.1.100", "dst_ip": "8.8.8.8", "dst_port": 443,
             "protocol": "tcp", "timestamp": 1704067201.0},
        ]

        findings = detector.detect_smb_movement(connections)

        assert len(findings) == 1
        assert findings[0]["src_ip"] == "192.168.1.100"
        assert findings[0]["dst_ip"] == "192.168.1.50"
        assert findings[0]["movement_type"] == "smb"

    def test_detect_rdp_internal_to_internal(self):
        """Should detect RDP connections between internal hosts."""
        from src.wireshark.hunting.lateral_movement import LateralMovementDetector

        detector = LateralMovementDetector()

        connections = [
            {"src_ip": "10.0.0.5", "dst_ip": "10.0.0.100", "dst_port": 3389,
             "protocol": "tcp", "timestamp": 1704067200.0},
        ]

        findings = detector.detect_rdp_movement(connections)

        assert len(findings) == 1
        assert findings[0]["movement_type"] == "rdp"

    def test_detect_winrm_connections(self):
        """Should detect WinRM connections."""
        from src.wireshark.hunting.lateral_movement import LateralMovementDetector

        detector = LateralMovementDetector()

        connections = [
            {"src_ip": "192.168.1.100", "dst_ip": "192.168.1.50", "dst_port": 5985,
             "protocol": "tcp", "timestamp": 1704067200.0},
            {"src_ip": "192.168.1.100", "dst_ip": "192.168.1.51", "dst_port": 5986,
             "protocol": "tcp", "timestamp": 1704067201.0},
        ]

        findings = detector.detect_winrm_movement(connections)

        assert len(findings) == 2
        assert all(f["movement_type"] == "winrm" for f in findings)

    def test_no_lateral_movement_to_external(self):
        """Should not flag connections to external IPs as lateral movement."""
        from src.wireshark.hunting.lateral_movement import LateralMovementDetector

        detector = LateralMovementDetector()

        connections = [
            {"src_ip": "192.168.1.100", "dst_ip": "8.8.8.8", "dst_port": 445,
             "protocol": "tcp", "timestamp": 1704067200.0},
        ]

        findings = detector.detect_smb_movement(connections)

        # External destination should not be flagged as lateral movement
        assert len(findings) == 0

    def test_detect_multiple_host_enumeration(self):
        """Should detect scanning multiple hosts on same port."""
        from src.wireshark.hunting.lateral_movement import LateralMovementDetector

        detector = LateralMovementDetector()

        # Single source hitting many internal hosts on port 445
        connections = [
            {"src_ip": "192.168.1.100", "dst_ip": f"192.168.1.{i}", "dst_port": 445,
             "protocol": "tcp", "timestamp": 1704067200.0 + i}
            for i in range(10, 20)
        ]

        findings = detector.detect_enumeration(connections, min_targets=5)

        assert len(findings) == 1
        assert findings[0]["source_ip"] == "192.168.1.100"
        assert findings[0]["target_count"] >= 5

    def test_detect_all_lateral_movement(self):
        """Should detect all types of lateral movement."""
        from src.wireshark.hunting.lateral_movement import LateralMovementDetector

        detector = LateralMovementDetector()

        connections = [
            {"src_ip": "192.168.1.100", "dst_ip": "192.168.1.50", "dst_port": 445,
             "protocol": "tcp", "timestamp": 1704067200.0},
            {"src_ip": "192.168.1.100", "dst_ip": "192.168.1.51", "dst_port": 3389,
             "protocol": "tcp", "timestamp": 1704067201.0},
            {"src_ip": "192.168.1.100", "dst_ip": "192.168.1.52", "dst_port": 5985,
             "protocol": "tcp", "timestamp": 1704067202.0},
        ]

        results = detector.detect_all(connections)

        assert "smb_findings" in results
        assert "rdp_findings" in results
        assert "winrm_findings" in results
        assert len(results["smb_findings"]) == 1
        assert len(results["rdp_findings"]) == 1
        assert len(results["winrm_findings"]) == 1

    def test_detect_psexec_pattern(self):
        """Should detect PsExec-like patterns (SMB + service creation)."""
        from src.wireshark.hunting.lateral_movement import LateralMovementDetector

        detector = LateralMovementDetector()

        # PsExec typically: SMB connection + admin share access + service pipe
        connections = [
            {"src_ip": "192.168.1.100", "dst_ip": "192.168.1.50", "dst_port": 445,
             "protocol": "tcp", "timestamp": 1704067200.0, "smb_path": "\\\\192.168.1.50\\ADMIN$"},
            {"src_ip": "192.168.1.100", "dst_ip": "192.168.1.50", "dst_port": 445,
             "protocol": "tcp", "timestamp": 1704067201.0, "smb_pipe": "\\pipe\\svcctl"},
        ]

        findings = detector.detect_psexec_pattern(connections)

        assert len(findings) >= 1

    def test_calculate_risk_score(self):
        """Should calculate risk score for lateral movement."""
        from src.wireshark.hunting.lateral_movement import LateralMovementDetector

        detector = LateralMovementDetector()

        # High risk: SMB to admin share from single source to multiple targets
        finding = {
            "src_ip": "192.168.1.100",
            "dst_ip": "192.168.1.50",
            "movement_type": "smb",
            "admin_share_access": True,
            "pipe_access": True
        }

        score = detector.calculate_risk_score(finding)

        assert score >= 7  # High risk

    def test_detect_from_pcap(self):
        """Should detect lateral movement from PCAP file."""
        from src.wireshark.hunting.lateral_movement import LateralMovementDetector

        pcap_files = list(TEST_PCAP_DIR.glob("**/*.pcap"))
        if not pcap_files:
            pytest.skip("No test pcap files available")

        detector = LateralMovementDetector()
        results = detector.detect_from_pcap(str(pcap_files[0]))

        assert "smb_findings" in results
        assert "rdp_findings" in results
        assert "winrm_findings" in results
        assert "summary" in results
