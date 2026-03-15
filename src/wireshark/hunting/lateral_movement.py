# src/wireshark/hunting/lateral_movement.py
"""Lateral movement detection (SMB/RDP/WinRM/NTLM)."""
import logging
from collections import defaultdict
from typing import Any

from src.wireshark.baseline.defaults import is_internal_ip

logger = logging.getLogger(__name__)

# Lateral movement ports
LATERAL_MOVEMENT_PORTS = {
    "smb": [445, 139],
    "rdp": [3389],
    "winrm": [5985, 5986],
    "ssh": [22],
    "wmi": [135],
}

# Admin shares and suspicious pipes
ADMIN_SHARES = ["ADMIN$", "C$", "D$", "IPC$"]
SUSPICIOUS_PIPES = ["svcctl", "atsvc", "eventlog", "lsass", "netlogon", "samr"]


class LateralMovementDetector:
    """Detect lateral movement patterns in network traffic."""

    def __init__(self, baseline: dict | None = None):
        """Initialize detector with optional baseline."""
        self.baseline = baseline or {}

    def detect_smb_movement(
        self,
        connections: list[dict],
        internal_only: bool = True
    ) -> list[dict]:
        """Detect SMB-based lateral movement.

        Args:
            connections: List of connection dictionaries
            internal_only: Only flag internal-to-internal connections

        Returns:
            List of lateral movement findings
        """
        findings = []

        for conn in connections:
            dst_port = conn.get("dst_port")
            if dst_port not in LATERAL_MOVEMENT_PORTS["smb"]:
                continue

            src_ip = conn.get("src_ip", "")
            dst_ip = conn.get("dst_ip", "")

            # Check if both are internal
            if internal_only:
                if not (is_internal_ip(src_ip) and is_internal_ip(dst_ip)):
                    continue

            finding = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "movement_type": "smb",
                "timestamp": conn.get("timestamp"),
                "protocol": conn.get("protocol", "tcp"),
                "smb_path": conn.get("smb_path"),
                "smb_pipe": conn.get("smb_pipe"),
                "admin_share_access": self._is_admin_share(conn.get("smb_path", "")),
                "pipe_access": self._is_suspicious_pipe(conn.get("smb_pipe", ""))
            }
            findings.append(finding)

        return findings

    def detect_rdp_movement(
        self,
        connections: list[dict],
        internal_only: bool = True
    ) -> list[dict]:
        """Detect RDP-based lateral movement.

        Args:
            connections: List of connection dictionaries
            internal_only: Only flag internal-to-internal connections

        Returns:
            List of lateral movement findings
        """
        findings = []

        for conn in connections:
            dst_port = conn.get("dst_port")
            if dst_port not in LATERAL_MOVEMENT_PORTS["rdp"]:
                continue

            src_ip = conn.get("src_ip", "")
            dst_ip = conn.get("dst_ip", "")

            # Check if both are internal
            if internal_only:
                if not (is_internal_ip(src_ip) and is_internal_ip(dst_ip)):
                    continue

            finding = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "movement_type": "rdp",
                "timestamp": conn.get("timestamp"),
                "protocol": conn.get("protocol", "tcp")
            }
            findings.append(finding)

        return findings

    def detect_winrm_movement(
        self,
        connections: list[dict],
        internal_only: bool = True
    ) -> list[dict]:
        """Detect WinRM-based lateral movement.

        Args:
            connections: List of connection dictionaries
            internal_only: Only flag internal-to-internal connections

        Returns:
            List of lateral movement findings
        """
        findings = []

        for conn in connections:
            dst_port = conn.get("dst_port")
            if dst_port not in LATERAL_MOVEMENT_PORTS["winrm"]:
                continue

            src_ip = conn.get("src_ip", "")
            dst_ip = conn.get("dst_ip", "")

            # Check if both are internal
            if internal_only:
                if not (is_internal_ip(src_ip) and is_internal_ip(dst_ip)):
                    continue

            finding = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "movement_type": "winrm",
                "timestamp": conn.get("timestamp"),
                "protocol": conn.get("protocol", "tcp")
            }
            findings.append(finding)

        return findings

    def detect_enumeration(
        self,
        connections: list[dict],
        min_targets: int = 5,
        ports: list[int] | None = None
    ) -> list[dict]:
        """Detect host enumeration (single source targeting many hosts).

        Args:
            connections: List of connection dictionaries
            min_targets: Minimum number of targets to flag as enumeration
            ports: Ports to check (defaults to lateral movement ports)

        Returns:
            List of enumeration findings
        """
        if ports is None:
            ports = []
            for port_list in LATERAL_MOVEMENT_PORTS.values():
                ports.extend(port_list)

        # Group by source IP and port
        src_targets = defaultdict(lambda: defaultdict(set))

        for conn in connections:
            dst_port = conn.get("dst_port")
            if dst_port not in ports:
                continue

            src_ip = conn.get("src_ip", "")
            dst_ip = conn.get("dst_ip", "")

            # Only consider internal targets
            if is_internal_ip(dst_ip):
                src_targets[src_ip][dst_port].add(dst_ip)

        findings = []
        for src_ip, port_targets in src_targets.items():
            for port, targets in port_targets.items():
                if len(targets) >= min_targets:
                    findings.append({
                        "source_ip": src_ip,
                        "port": port,
                        "target_count": len(targets),
                        "targets": sorted(list(targets)),
                        "finding_type": "enumeration"
                    })

        return findings

    def detect_psexec_pattern(
        self,
        connections: list[dict]
    ) -> list[dict]:
        """Detect PsExec-like patterns.

        PsExec pattern:
        1. SMB connection to target
        2. Access to admin share (ADMIN$, C$)
        3. Access to service control pipe (svcctl)

        Args:
            connections: List of connection dictionaries

        Returns:
            List of PsExec pattern findings
        """
        # Group by source-destination pair
        pairs = defaultdict(list)

        for conn in connections:
            dst_port = conn.get("dst_port")
            if dst_port not in LATERAL_MOVEMENT_PORTS["smb"]:
                continue

            src_ip = conn.get("src_ip", "")
            dst_ip = conn.get("dst_ip", "")
            pairs[(src_ip, dst_ip)].append(conn)

        findings = []
        for (src_ip, dst_ip), conns in pairs.items():
            has_admin_share = False
            has_service_pipe = False

            for conn in conns:
                smb_path = conn.get("smb_path", "")
                smb_pipe = conn.get("smb_pipe", "")

                if self._is_admin_share(smb_path):
                    has_admin_share = True
                if self._is_suspicious_pipe(smb_pipe):
                    has_service_pipe = True

            # PsExec pattern requires admin share + service pipe
            if has_admin_share and has_service_pipe:
                findings.append({
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "movement_type": "psexec_pattern",
                    "admin_share_access": True,
                    "pipe_access": True,
                    "confidence": "high",
                    "connection_count": len(conns)
                })
            elif has_admin_share or has_service_pipe:
                # Partial pattern - still suspicious
                findings.append({
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "movement_type": "suspicious_smb",
                    "admin_share_access": has_admin_share,
                    "pipe_access": has_service_pipe,
                    "confidence": "medium",
                    "connection_count": len(conns)
                })

        return findings

    def detect_all(
        self,
        connections: list[dict],
        internal_only: bool = True
    ) -> dict[str, Any]:
        """Detect all types of lateral movement.

        Args:
            connections: List of connection dictionaries
            internal_only: Only flag internal-to-internal

        Returns:
            Dictionary with all findings
        """
        smb_findings = self.detect_smb_movement(connections, internal_only)
        rdp_findings = self.detect_rdp_movement(connections, internal_only)
        winrm_findings = self.detect_winrm_movement(connections, internal_only)
        enumeration = self.detect_enumeration(connections)
        psexec = self.detect_psexec_pattern(connections)

        return {
            "smb_findings": smb_findings,
            "rdp_findings": rdp_findings,
            "winrm_findings": winrm_findings,
            "enumeration_findings": enumeration,
            "psexec_patterns": psexec,
            "summary": {
                "total_smb": len(smb_findings),
                "total_rdp": len(rdp_findings),
                "total_winrm": len(winrm_findings),
                "enumeration_detected": len(enumeration) > 0,
                "psexec_detected": len(psexec) > 0
            }
        }

    def calculate_risk_score(self, finding: dict) -> int:
        """Calculate risk score for a lateral movement finding.

        Args:
            finding: Lateral movement finding dictionary

        Returns:
            Risk score (1-10)
        """
        score = 3  # Base score for any lateral movement

        movement_type = finding.get("movement_type", "")

        # Type-based scoring
        if movement_type == "psexec_pattern":
            score += 4
        elif movement_type == "smb" or movement_type == "rdp":
            score += 2
        elif movement_type == "winrm":
            score += 3  # WinRM is often used for remote management attacks

        # Admin share access
        if finding.get("admin_share_access"):
            score += 2

        # Pipe access
        if finding.get("pipe_access"):
            score += 1

        return min(10, score)

    def detect_from_pcap(
        self,
        pcap_path: str,
        executor=None
    ) -> dict[str, Any]:
        """Detect lateral movement from a PCAP file.

        Args:
            pcap_path: Path to PCAP file
            executor: Optional TSharkExecutor instance

        Returns:
            Dictionary with all findings
        """
        from src.wireshark.core.tshark_executor import TSharkExecutor

        if executor is None:
            executor = TSharkExecutor()

        # Extract connection data for lateral movement ports
        all_ports = []
        for port_list in LATERAL_MOVEMENT_PORTS.values():
            all_ports.extend(port_list)

        port_filter = " or ".join(f"tcp.dstport == {p}" for p in all_ports)

        results = executor.execute_and_parse_fields(
            pcap_path=pcap_path,
            fields=[
                "ip.src", "ip.dst", "tcp.dstport",
                "frame.time_epoch", "smb.path", "smb.file"
            ],
            display_filter=f"tcp and ({port_filter})",
            timeout=300
        )

        # Build connection list
        connections = []
        for row in results:
            try:
                conn = {
                    "src_ip": row.get("ip.src", ""),
                    "dst_ip": row.get("ip.dst", ""),
                    "dst_port": int(row.get("tcp.dstport", 0)),
                    "protocol": "tcp",
                    "timestamp": float(row.get("frame.time_epoch", 0)),
                    "smb_path": row.get("smb.path", ""),
                    "smb_pipe": row.get("smb.file", "")
                }
                connections.append(conn)
            except (ValueError, TypeError):
                continue

        # Run all detection
        results = self.detect_all(connections)
        results["pcap_path"] = pcap_path
        results["connection_count"] = len(connections)

        return results

    def _is_admin_share(self, path: str) -> bool:
        """Check if path is an admin share."""
        if not path:
            return False
        path_upper = path.upper()
        return any(share in path_upper for share in ADMIN_SHARES)

    def _is_suspicious_pipe(self, pipe: str) -> bool:
        """Check if pipe is suspicious."""
        if not pipe:
            return False
        pipe_lower = pipe.lower()
        return any(p in pipe_lower for p in SUSPICIOUS_PIPES)

    def get_lateral_movement_summary(
        self,
        results: dict[str, Any]
    ) -> str:
        """Generate human-readable summary of lateral movement findings.

        Args:
            results: Results from detect_all()

        Returns:
            Summary string
        """
        lines = []
        lines.append("=" * 60)
        lines.append(" LATERAL MOVEMENT ANALYSIS")
        lines.append("=" * 60)
        lines.append("")

        summary = results.get("summary", {})
        lines.append(f"SMB Connections: {summary.get('total_smb', 0)}")
        lines.append(f"RDP Connections: {summary.get('total_rdp', 0)}")
        lines.append(f"WinRM Connections: {summary.get('total_winrm', 0)}")
        lines.append("")

        if summary.get("enumeration_detected"):
            lines.append("[!] Host enumeration detected!")
            for enum in results.get("enumeration_findings", []):
                lines.append(f"    Source: {enum['source_ip']}")
                lines.append(f"    Port: {enum['port']}")
                lines.append(f"    Targets: {enum['target_count']}")
            lines.append("")

        if summary.get("psexec_detected"):
            lines.append("[!] PsExec-like pattern detected!")
            for psexec in results.get("psexec_patterns", []):
                lines.append(f"    {psexec['src_ip']} -> {psexec['dst_ip']}")
            lines.append("")

        lines.append("=" * 60)

        return "\n".join(lines)
