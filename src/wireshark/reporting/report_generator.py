# src/wireshark/reporting/report_generator.py
"""NCSC-style incident report generator."""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from src.wireshark.reporting.timeline_visualizer import TimelineVisualizer

logger = logging.getLogger(__name__)

# NCSC Framework sections
NCSC_SECTIONS = ["IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"]


class ReportGenerator:
    """Generate NCSC-style incident reports."""

    def __init__(self):
        """Initialize report generator."""
        self.visualizer = TimelineVisualizer()

    def generate_report(
        self,
        pcap_path: str,
        findings: dict[str, Any],
        investigation_id: str | None = None,
        include_raw_json: bool = True,
    ) -> str:
        """Generate complete NCSC-style markdown report.

        Args:
            pcap_path: Path to analyzed PCAP file
            findings: Dictionary of all findings
            investigation_id: Optional investigation ID
            include_raw_json: Include raw JSON appendix

        Returns:
            Markdown report string
        """
        if investigation_id is None:
            investigation_id = f"INV-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

        lines = []

        # Header
        lines.append(f"# Network Incident Report: {investigation_id}")
        lines.append("")
        lines.append(f"**Generated:** {self.format_timestamp(datetime.now())}")
        lines.append(f"**PCAP Analyzed:** {Path(pcap_path).name}")
        lines.append("")
        lines.append("---")
        lines.append("")

        # Executive Summary
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(self.generate_executive_summary(findings))
        lines.append("")
        lines.append("---")
        lines.append("")

        # IDENTIFY Section
        lines.append("## IDENTIFY")
        lines.append("")
        lines.append("### Affected Assets")
        lines.append("")
        assets = self._extract_affected_assets(findings)
        lines.append(self.generate_affected_assets(assets))
        lines.append("")

        # Attack timeline if available
        if findings.get("beaconing") or findings.get("lateral_movement"):
            lines.append("### Attack Timeline")
            lines.append("")
            lines.append("```")
            lines.append(self._generate_attack_timeline(findings))
            lines.append("```")
            lines.append("")

        lines.append("---")
        lines.append("")

        # PROTECT Section
        lines.append("## PROTECT")
        lines.append("")
        lines.append("### Immediate Actions Required")
        lines.append("")
        actions = self._generate_immediate_actions(findings)
        for action in actions:
            lines.append(f"- [ ] {action}")
        lines.append("")
        lines.append("---")
        lines.append("")

        # DETECT Section
        lines.append("## DETECT")
        lines.append("")
        lines.append("### Indicators of Compromise")
        lines.append("")
        iocs = findings.get("iocs", [])
        lines.append(self.generate_ioc_table(iocs))
        lines.append("")

        lines.append("### Detection Rules Recommended")
        lines.append("")
        rules = self._generate_detection_rules(findings)
        for rule in rules:
            lines.append(f"- {rule}")
        lines.append("")
        lines.append("---")
        lines.append("")

        # RESPOND Section
        lines.append("## RESPOND")
        lines.append("")
        lines.append("### Containment Steps")
        lines.append("")
        steps = self.generate_containment_steps(findings)
        for i, step in enumerate(steps, 1):
            lines.append(f"{i}. {step}")
        lines.append("")

        lines.append("### Evidence Preserved")
        lines.append("")
        lines.append(f"- PCAP file: `{pcap_path}`")
        lines.append(f"- Analysis timestamp: {self.format_timestamp(datetime.now())}")
        lines.append("")
        lines.append("---")
        lines.append("")

        # RECOVER Section
        lines.append("## RECOVER")
        lines.append("")
        lines.append("### Remediation Checklist")
        lines.append("")
        remediation = self._generate_remediation_checklist(findings)
        for item in remediation:
            lines.append(f"- [ ] {item}")
        lines.append("")
        lines.append("---")
        lines.append("")

        # Appendix
        if include_raw_json:
            lines.append("## Appendix: Raw IoCs (JSON)")
            lines.append("")
            lines.append("```json")
            lines.append(json.dumps(self.export_to_json(investigation_id, findings), indent=2))
            lines.append("```")
            lines.append("")

        return "\n".join(lines)

    def generate_executive_summary(self, findings: dict[str, Any]) -> str:
        """Generate executive summary section.

        Args:
            findings: All findings dictionary

        Returns:
            Executive summary text
        """
        summary_parts = []

        beacons = findings.get("beaconing", [])
        anomalies = findings.get("anomalies", [])
        iocs = findings.get("iocs", [])
        lateral = findings.get("lateral_movement", [])

        if beacons:
            high_conf = [b for b in beacons if b.get("confidence") == "high"]
            summary_parts.append(
                f"Detected {len(beacons)} potential beaconing patterns ({len(high_conf)} high confidence)."
            )

        if lateral:
            summary_parts.append(f"Identified {len(lateral)} lateral movement indicators.")

        if anomalies:
            summary_parts.append(f"Found {len(anomalies)} network anomalies requiring investigation.")

        if iocs:
            summary_parts.append(f"Extracted {len(iocs)} indicators of compromise.")

        if not summary_parts:
            return "No significant findings detected during analysis."

        return " ".join(summary_parts)

    def generate_ioc_table(self, iocs: list[dict]) -> str:
        """Generate IoC table in markdown format.

        Args:
            iocs: List of IoC dictionaries

        Returns:
            Markdown table string
        """
        if not iocs:
            return "*No IoCs extracted.*"

        lines = []
        lines.append("| Type | Value | Confidence | First Seen |")
        lines.append("|------|-------|------------|------------|")

        for ioc in iocs:
            ioc_type = ioc.get("type", "unknown")
            value = ioc.get("value", "N/A")
            confidence = ioc.get("confidence", "N/A")
            first_seen = ioc.get("first_seen", "N/A")

            # Truncate long values
            if len(str(value)) > 40:
                value = str(value)[:37] + "..."

            lines.append(f"| {ioc_type} | {value} | {confidence} | {first_seen} |")

        return "\n".join(lines)

    def generate_affected_assets(self, assets: list[dict]) -> str:
        """Generate affected assets section.

        Args:
            assets: List of asset dictionaries

        Returns:
            Markdown formatted assets list
        """
        if not assets:
            return "*No affected assets identified.*"

        lines = []
        for asset in assets:
            ip = asset.get("ip", "unknown")
            hostname = asset.get("hostname", "N/A")
            role = asset.get("role", "unknown")

            lines.append(f"- **{ip}** ({hostname}) - Role: {role}")

        return "\n".join(lines)

    def generate_recommendations(self, findings: dict[str, Any]) -> list[str]:
        """Generate recommended actions.

        Args:
            findings: All findings

        Returns:
            List of recommendation strings
        """
        recommendations = []

        if findings.get("beaconing"):
            recommendations.append("Block identified C2 IP addresses at firewall")
            recommendations.append("Hunt for additional beaconing on affected hosts")

        if findings.get("lateral_movement"):
            movements = findings.get("lateral_movement", [])
            psexec = [m for m in movements if m.get("movement_type") == "psexec_pattern"]
            if psexec:
                recommendations.append("Investigate potential PsExec/remote execution")
                recommendations.append("Review SMB access logs on target systems")

            recommendations.append("Isolate affected hosts for forensic analysis")

        if findings.get("anomalies"):
            recommendations.append("Review anomalous traffic patterns")
            recommendations.append("Update baseline with legitimate traffic if false positive")

        if not recommendations:
            recommendations.append("Continue monitoring for suspicious activity")

        return recommendations

    def format_timestamp(self, dt: datetime) -> str:
        """Format timestamps consistently.

        Args:
            dt: Datetime object

        Returns:
            Formatted timestamp string
        """
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")

    def generate_containment_steps(self, findings: dict[str, Any]) -> list[str]:
        """Generate containment steps based on findings.

        Args:
            findings: All findings

        Returns:
            List of containment step strings
        """
        steps = []

        beacons = findings.get("beaconing", [])
        lateral = findings.get("lateral_movement", [])

        if beacons:
            c2_ips = set(b.get("dst_ip") for b in beacons if b.get("dst_ip"))
            if c2_ips:
                steps.append(f"Block C2 IPs at perimeter: {', '.join(c2_ips)}")

            source_ips = set(b.get("src_ip") for b in beacons if b.get("src_ip"))
            if source_ips:
                steps.append(f"Isolate potentially infected hosts: {', '.join(source_ips)}")

        if lateral:
            target_ips = set(m.get("dst_ip") for m in lateral if m.get("dst_ip"))
            if target_ips:
                steps.append(f"Verify integrity of lateral movement targets: {', '.join(target_ips)}")

            steps.append("Disable compromised credentials if identified")

        if not steps:
            steps.append("No immediate containment actions required")
            steps.append("Continue monitoring for suspicious activity")

        return steps

    def export_to_json(self, investigation_id: str, findings: dict[str, Any]) -> dict[str, Any]:
        """Export report data as JSON.

        Args:
            investigation_id: Investigation identifier
            findings: All findings

        Returns:
            JSON-serializable dictionary
        """
        return {
            "investigation_id": investigation_id,
            "generated_at": datetime.now().isoformat(),
            "iocs": findings.get("iocs", []),
            "beaconing_detected": len(findings.get("beaconing", [])),
            "anomalies_detected": len(findings.get("anomalies", [])),
            "lateral_movement_detected": len(findings.get("lateral_movement", [])),
            "findings_summary": {
                "beaconing": findings.get("beaconing", []),
                "anomalies": findings.get("anomalies", []),
                "lateral_movement": findings.get("lateral_movement", []),
            },
        }

    def _extract_affected_assets(self, findings: dict[str, Any]) -> list[dict]:
        """Extract affected assets from findings.

        Args:
            findings: All findings

        Returns:
            List of asset dictionaries
        """
        assets = {}

        # Extract from beaconing
        for beacon in findings.get("beaconing", []):
            src_ip = beacon.get("src_ip")
            if src_ip and src_ip not in assets:
                assets[src_ip] = {"ip": src_ip, "hostname": beacon.get("hostname", "N/A"), "role": "source"}

        # Extract from lateral movement
        for mov in findings.get("lateral_movement", []):
            src_ip = mov.get("src_ip")
            dst_ip = mov.get("dst_ip")

            if src_ip and src_ip not in assets:
                assets[src_ip] = {"ip": src_ip, "hostname": "N/A", "role": "source"}
            if dst_ip and dst_ip not in assets:
                assets[dst_ip] = {"ip": dst_ip, "hostname": "N/A", "role": "target"}

        return list(assets.values())

    def _generate_attack_timeline(self, findings: dict[str, Any]) -> str:
        """Generate attack timeline visualization.

        Args:
            findings: All findings

        Returns:
            ASCII timeline string
        """
        events = []

        # Add beaconing events
        for beacon in findings.get("beaconing", []):
            events.append(
                {
                    "timestamp": beacon.get("timestamp", 0),
                    "src_ip": beacon.get("src_ip", "unknown"),
                    "dst_ip": beacon.get("dst_ip", "unknown"),
                }
            )

        if events:
            target_ip = events[0].get("dst_ip", "unknown")
            return self.visualizer.generate_beaconing_timeline(events, target_ip)

        return "No timeline data available."

    def _generate_immediate_actions(self, findings: dict[str, Any]) -> list[str]:
        """Generate immediate action items.

        Args:
            findings: All findings

        Returns:
            List of action strings
        """
        actions = []

        if findings.get("beaconing"):
            actions.append("Block identified C2 addresses at firewall")
            actions.append("Initiate endpoint isolation for beaconing hosts")

        if findings.get("lateral_movement"):
            actions.append("Reset credentials for affected accounts")
            actions.append("Enable enhanced logging on target systems")

        if findings.get("anomalies"):
            actions.append("Review and triage anomalous connections")

        if not actions:
            actions.append("Monitor for additional suspicious activity")

        return actions

    def _generate_detection_rules(self, findings: dict[str, Any]) -> list[str]:
        """Generate recommended detection rules.

        Args:
            findings: All findings

        Returns:
            List of rule suggestions
        """
        rules = []

        if findings.get("beaconing"):
            rules.append("Alert on regular-interval connections to flagged IPs")
            rules.append("Monitor for DNS queries to identified malicious domains")

        if findings.get("lateral_movement"):
            rules.append("Alert on SMB connections to admin shares (ADMIN$, C$)")
            rules.append("Monitor for remote service creation (Event ID 7045)")

        if findings.get("anomalies"):
            for anomaly in findings.get("anomalies", []):
                if anomaly.get("type") == "unusual_port":
                    port = anomaly.get("port")
                    if port:
                        rules.append(f"Alert on connections to unusual port {port}")

        return rules

    def _generate_remediation_checklist(self, findings: dict[str, Any]) -> list[str]:
        """Generate remediation checklist.

        Args:
            findings: All findings

        Returns:
            List of remediation items
        """
        items = []

        if findings.get("beaconing"):
            items.append("Reimage potentially infected endpoints")
            items.append("Review and update endpoint protection signatures")
            items.append("Conduct memory forensics on affected systems")

        if findings.get("lateral_movement"):
            items.append("Rotate all potentially compromised credentials")
            items.append("Review Active Directory for unauthorized changes")
            items.append("Audit service accounts and scheduled tasks")

        items.append("Update network baselines with new threat indicators")
        items.append("Document lessons learned for incident response improvement")

        return items

    def save_report(self, report: str, output_path: str) -> bool:
        """Save report to file.

        Args:
            report: Report content
            output_path: Output file path

        Returns:
            True if successful
        """
        try:
            Path(output_path).write_text(report)
            logger.info(f"Report saved to {output_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save report: {e}")
            return False
