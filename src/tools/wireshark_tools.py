# src/tools/wireshark_tools.py
"""Wireshark/TShark MCP tools for network traffic analysis."""

import logging
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from src.storage.auto_capture import auto_capture_wireshark_results

logger = logging.getLogger(__name__)


class WiresharkTools:
    """MCP tools for Wireshark/TShark network analysis."""

    def __init__(self):
        """Initialize Wireshark tools."""
        # Lazy imports to avoid circular dependencies
        self._executor = None
        self._analyzer = None
        self._baseline_builder = None
        self._anomaly_detector = None
        self._beaconing_detector = None
        self._lateral_movement_detector = None
        self._ioc_hunter = None
        self._session_tracker = None
        self._object_extractor = None
        self._report_generator = None

    @property
    def executor(self):
        """Lazy load TShark executor."""
        if self._executor is None:
            from src.wireshark.core.tshark_executor import TSharkExecutor

            self._executor = TSharkExecutor()
        return self._executor

    @property
    def analyzer(self):
        """Lazy load PCAP analyzer."""
        if self._analyzer is None:
            from src.wireshark.core.pcap_analyzer import PcapAnalyzer

            self._analyzer = PcapAnalyzer()
        return self._analyzer

    @property
    def baseline_builder(self):
        """Lazy load baseline builder."""
        if self._baseline_builder is None:
            from src.wireshark.baseline.baseline_builder import BaselineBuilder

            self._baseline_builder = BaselineBuilder()
        return self._baseline_builder

    @property
    def anomaly_detector(self):
        """Lazy load anomaly detector."""
        if self._anomaly_detector is None:
            from src.wireshark.hunting.anomaly_detector import AnomalyDetector

            self._anomaly_detector = AnomalyDetector()
        return self._anomaly_detector

    @property
    def beaconing_detector(self):
        """Lazy load beaconing detector."""
        if self._beaconing_detector is None:
            from src.wireshark.hunting.beaconing_detector import BeaconingDetector

            self._beaconing_detector = BeaconingDetector()
        return self._beaconing_detector

    @property
    def lateral_movement_detector(self):
        """Lazy load lateral movement detector."""
        if self._lateral_movement_detector is None:
            from src.wireshark.hunting.lateral_movement import LateralMovementDetector

            self._lateral_movement_detector = LateralMovementDetector()
        return self._lateral_movement_detector

    @property
    def ioc_hunter(self):
        """Lazy load IoC hunter."""
        if self._ioc_hunter is None:
            from src.wireshark.hunting.ioc_hunter import IoCHunter

            self._ioc_hunter = IoCHunter()
        return self._ioc_hunter

    @property
    def session_tracker(self):
        """Lazy load session tracker."""
        if self._session_tracker is None:
            from src.wireshark.hunting.session_tracker import SessionTracker

            self._session_tracker = SessionTracker()
        return self._session_tracker

    @property
    def object_extractor(self):
        """Lazy load object extractor."""
        if self._object_extractor is None:
            from src.wireshark.extraction.object_extractor import ObjectExtractor

            self._object_extractor = ObjectExtractor()
        return self._object_extractor

    @property
    def report_generator(self):
        """Lazy load report generator."""
        if self._report_generator is None:
            from src.wireshark.reporting.report_generator import ReportGenerator

            self._report_generator = ReportGenerator()
        return self._report_generator

    def register_tools(self, mcp: FastMCP):
        """Register all Wireshark MCP tools.

        Args:
            mcp: FastMCP instance
        """
        tools_instance = self

        # Tool 1: PCAP Overview
        @mcp.tool()
        def pcap_overview(pcap_path: str) -> dict[str, Any]:
            """
            Load and analyze a PCAP file to get an overview of the network traffic.

            This is typically the first step in network forensics - getting a high-level
            view of what's in the capture before diving deeper.

            Args:
                pcap_path: Path to the PCAP file to analyze

            Returns:
                Dictionary containing:
                - packet_count: Total number of packets
                - time_range: Start and end timestamps
                - protocols: Protocol distribution
                - top_talkers: Most active IP addresses
                - file_size: Size of the PCAP file

            Example:
                pcap_overview("/path/to/capture.pcap")
            """
            result = tools_instance._pcap_overview(pcap_path)
            return auto_capture_wireshark_results(
                result, "pcap_overview", query_description=f"PCAP overview: {pcap_path}"
            )

        # Tool 2: Build Baseline
        @mcp.tool()
        def build_baseline(pcap_path: str, baseline_name: str, description: str | None = None) -> dict[str, Any]:
            """
            Build a baseline from normal traffic to compare against suspicious activity.

            Analyzes a PCAP of known-good traffic and creates a baseline profile
            that can be used to detect anomalies in other captures.

            Args:
                pcap_path: Path to PCAP containing normal/baseline traffic
                baseline_name: Name for the baseline
                description: Optional description

            Returns:
                Dictionary with baseline statistics and save location

            Example:
                build_baseline(
                    pcap_path="/path/to/normal_traffic.pcap",
                    baseline_name="corporate_baseline"
                )
            """
            result = tools_instance._build_baseline(pcap_path, baseline_name, description)
            return auto_capture_wireshark_results(
                result, "build_baseline", query_description=f"Baseline: {baseline_name}"
            )

        # Tool 3: Hunt IoCs
        @mcp.tool()
        def hunt_iocs(pcap_path: str, iocs: list[str], ioc_type: str | None = None) -> dict[str, Any]:
            """
            Hunt for specific Indicators of Compromise (IoCs) in a PCAP file.

            Searches for known-bad IPs, domains, hashes, or other indicators
            within the network traffic.

            Args:
                pcap_path: Path to PCAP file to search
                iocs: List of IoC values to search for
                ioc_type: Type of IoC (ip, domain, hash) - auto-detected if not specified

            Returns:
                Dictionary with matches found and their context

            Example:
                hunt_iocs(
                    pcap_path="/path/to/suspicious.pcap",
                    iocs=["1.2.3.4", "evil.com", "abc123hash"]
                )
            """
            result = tools_instance._hunt_iocs(pcap_path, iocs, ioc_type)
            return auto_capture_wireshark_results(
                result, "hunt_iocs", query_description=f"IoC hunt: {len(iocs)} indicators"
            )

        # Tool 4: Hunt Anomalies
        @mcp.tool()
        def hunt_anomalies(pcap_path: str, baseline_name: str | None = None) -> dict[str, Any]:
            """
            Detect network anomalies by comparing against baseline or defaults.

            Identifies unusual ports, protocol misuse, DNS anomalies, and other
            suspicious patterns in network traffic.

            Args:
                pcap_path: Path to PCAP file to analyze
                baseline_name: Optional baseline to compare against (uses defaults if not specified)

            Returns:
                Dictionary with detected anomalies categorized by type

            Example:
                hunt_anomalies("/path/to/suspicious.pcap")
            """
            result = tools_instance._hunt_anomalies(pcap_path, baseline_name)
            return auto_capture_wireshark_results(
                result, "hunt_anomalies", query_description=f"Anomaly hunt: {pcap_path}"
            )

        # Tool 5: Track Sessions
        @mcp.tool()
        def track_sessions(
            pcap_path: str, protocol: str = "tcp", port_filter: list[int] | None = None
        ) -> dict[str, Any]:
            """
            Track and reconstruct network sessions from PCAP.

            Follows TCP/UDP streams, identifying session patterns, data volumes,
            and communication timelines.

            Args:
                pcap_path: Path to PCAP file
                protocol: Protocol to track (tcp or udp)
                port_filter: Optional list of ports to filter

            Returns:
                Dictionary with session details and summary

            Example:
                track_sessions("/path/to/capture.pcap", protocol="tcp")
            """
            result = tools_instance._track_sessions(pcap_path, protocol, port_filter)
            return auto_capture_wireshark_results(
                result, "track_sessions", query_description=f"Session tracking: {protocol}"
            )

        # Tool 6: Extract Objects
        @mcp.tool()
        def extract_objects(pcap_path: str, protocol: str = "http", store_files: bool = False) -> dict[str, Any]:
            """
            Extract transferred objects (files) from network traffic.

            Carves out HTTP, SMB, and other protocol objects with SHA256 hashes.
            By default, only extracts metadata and hashes for safety.

            Args:
                pcap_path: Path to PCAP file
                protocol: Protocol to extract from (http, smb, tftp)
                store_files: Whether to save extracted files (default: False, metadata only)

            Returns:
                Dictionary with extracted objects, hashes, and metadata

            Example:
                extract_objects("/path/to/capture.pcap", protocol="http")
            """
            result = tools_instance._extract_objects(pcap_path, protocol, store_files)
            return auto_capture_wireshark_results(
                result, "extract_objects", query_description=f"Object extraction: {protocol}"
            )

        # Tool 7: Detect Beaconing
        @mcp.tool()
        def detect_beaconing(
            pcap_path: str, min_connections: int = 10, max_jitter_percent: float = 15.0
        ) -> dict[str, Any]:
            """
            Detect C2 beaconing patterns based on connection timing analysis.

            Identifies hosts that communicate at regular intervals, which is
            characteristic of command-and-control malware.

            Args:
                pcap_path: Path to PCAP file
                min_connections: Minimum connections to analyze (default: 10)
                max_jitter_percent: Maximum jitter percentage for beacon detection (default: 15%)

            Returns:
                Dictionary with beacon patterns and ASCII timeline visualization

            Example:
                detect_beaconing("/path/to/suspicious.pcap")
            """
            result = tools_instance._detect_beaconing(pcap_path, min_connections, max_jitter_percent)
            return auto_capture_wireshark_results(result, "detect_beaconing", query_description="Beaconing detection")

        # Tool 8: Detect Lateral Movement
        @mcp.tool()
        def detect_lateral_movement(pcap_path: str, internal_only: bool = True) -> dict[str, Any]:
            """
            Detect lateral movement patterns in network traffic.

            Identifies SMB, RDP, WinRM, and other protocols commonly used for
            lateral movement within a network.

            Args:
                pcap_path: Path to PCAP file
                internal_only: Only flag internal-to-internal connections (default: True)

            Returns:
                Dictionary with lateral movement findings and risk scores

            Example:
                detect_lateral_movement("/path/to/internal_traffic.pcap")
            """
            result = tools_instance._detect_lateral_movement(pcap_path, internal_only)
            return auto_capture_wireshark_results(
                result, "detect_lateral_movement", query_description="Lateral movement detection"
            )

        # Tool 9: Generate IoCs
        @mcp.tool()
        def generate_iocs(pcap_path: str, min_confidence: int = 5) -> dict[str, Any]:
            """
            Generate structured IoC artifacts from PCAP analysis.

            Extracts and structures indicators found during analysis for use in
            threat intelligence and detection systems.

            Args:
                pcap_path: Path to PCAP file
                min_confidence: Minimum confidence level for IoCs (1-10)

            Returns:
                Dictionary with IoCs structured for export

            Example:
                generate_iocs("/path/to/analyzed.pcap", min_confidence=7)
            """
            result = tools_instance._generate_iocs(pcap_path, min_confidence)
            return auto_capture_wireshark_results(result, "generate_iocs", query_description="IoC generation")

        # Tool 10: Generate Report
        @mcp.tool()
        def generate_report(
            pcap_path: str, findings: dict[str, Any] | None = None, investigation_id: str | None = None
        ) -> dict[str, Any]:
            """
            Generate an NCSC-style incident report from analysis findings.

            Creates a structured markdown report following the IDENTIFY, PROTECT,
            DETECT, RESPOND, RECOVER framework.

            Args:
                pcap_path: Path to analyzed PCAP file
                findings: Optional pre-computed findings (if not provided, runs analysis)
                investigation_id: Optional investigation identifier

            Returns:
                Dictionary with the generated report

            Example:
                generate_report("/path/to/analyzed.pcap", investigation_id="INV-2024-001")
            """
            result = tools_instance._generate_report(pcap_path, findings, investigation_id)
            return auto_capture_wireshark_results(result, "generate_report", query_description="Report generation")

        # Tool 11: Decode Traffic (Utility)
        @mcp.tool()
        def decode_traffic(pcap_path: str, port: int, protocol: str) -> dict[str, Any]:
            """
            Force protocol interpretation on non-standard ports.

            Useful when services run on non-standard ports and need to be
            decoded as a specific protocol.

            Args:
                pcap_path: Path to PCAP file
                port: Port number to decode
                protocol: Protocol to decode as (http, https, dns, etc.)

            Returns:
                Decoded traffic summary

            Example:
                decode_traffic("/path/to/capture.pcap", port=8080, protocol="http")
            """
            result = tools_instance._decode_traffic(pcap_path, port, protocol)
            return auto_capture_wireshark_results(
                result, "decode_traffic", query_description=f"Decode {protocol} on port {port}"
            )

    # Internal implementation methods

    def _pcap_overview(self, pcap_path: str) -> dict[str, Any]:
        """Internal implementation of pcap_overview."""
        try:
            if not Path(pcap_path).exists():
                return {"error": f"PCAP file not found: {pcap_path}"}

            metadata = self.analyzer.get_metadata(pcap_path)
            if metadata is None:
                return {"error": "Failed to analyze PCAP file"}

            protocols = self.analyzer.get_protocol_hierarchy(pcap_path)
            top_talkers = self.analyzer.get_top_talkers(pcap_path)

            return {
                "pcap_path": pcap_path,
                "packet_count": metadata.packet_count,
                "duration_seconds": metadata.duration_seconds,
                "time_start": str(metadata.time_start) if metadata.time_start else None,
                "time_end": str(metadata.time_end) if metadata.time_end else None,
                "file_size_bytes": metadata.file_size_bytes,
                "protocols": [p.model_dump() if hasattr(p, "model_dump") else p for p in protocols],
                "top_talkers": [t.model_dump() if hasattr(t, "model_dump") else t for t in top_talkers],
            }
        except Exception as e:
            logger.error(f"Error in pcap_overview: {e}")
            return {"error": str(e)}

    def _build_baseline(self, pcap_path: str, baseline_name: str, description: str | None = None) -> dict[str, Any]:
        """Internal implementation of build_baseline."""
        try:
            if not Path(pcap_path).exists():
                return {"error": f"PCAP file not found: {pcap_path}"}

            baseline = self.baseline_builder.build_from_pcap(pcap_path=pcap_path, name=baseline_name)

            if baseline is None:
                return {"error": "Failed to build baseline"}

            # Save the baseline
            from src.wireshark.baseline.baseline_store import BaselineStore

            store = BaselineStore()
            save_path = store.save(baseline_name, baseline)

            # Count ports from both TCP and UDP
            observed_ports = baseline.get("observed_ports", {})
            tcp_ports = observed_ports.get("tcp", [])
            udp_ports = observed_ports.get("udp", [])
            total_ports = len(set(tcp_ports + udp_ports))

            return {
                "baseline_name": baseline_name,
                "description": description,
                "unique_ips": len(baseline.get("observed_ips", [])),
                "unique_ports": total_ports,
                "unique_domains": len(baseline.get("observed_domains", [])),
                "saved_to": str(save_path) if save_path else None,
            }
        except Exception as e:
            logger.error(f"Error in build_baseline: {e}")
            return {"error": str(e)}

    def _hunt_iocs(self, pcap_path: str, iocs: list[str], ioc_type: str | None = None) -> dict[str, Any]:
        """Internal implementation of hunt_iocs."""
        try:
            if not Path(pcap_path).exists():
                return {"error": f"PCAP file not found: {pcap_path}"}

            import re

            # Categorize IoCs by type
            ip_iocs = []
            domain_iocs = []
            hash_iocs = []

            ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
            hash_pattern = re.compile(r"^[a-fA-F0-9]{32,64}$")

            for ioc in iocs:
                if ioc_type == "ip" or (ioc_type is None and ip_pattern.match(ioc)):
                    ip_iocs.append(ioc)
                elif ioc_type == "hash" or (ioc_type is None and hash_pattern.match(ioc)):
                    hash_iocs.append(ioc)
                else:
                    # Assume domain if not IP or hash
                    domain_iocs.append(ioc)

            results = self.ioc_hunter.hunt_iocs_in_pcap(
                pcap_path=pcap_path,
                ip_iocs=ip_iocs if ip_iocs else None,
                domain_iocs=domain_iocs if domain_iocs else None,
                hash_iocs=hash_iocs if hash_iocs else None,
                executor=self.executor,
            )

            # Aggregate all matches
            all_matches = []
            all_matches.extend(results.get("ip_matches", []))
            all_matches.extend(results.get("domain_matches", []))
            all_matches.extend(results.get("hash_matches", []))

            return {
                "pcap_path": pcap_path,
                "iocs_searched": len(iocs),
                "matches": all_matches,
                "found": len(all_matches) > 0,
                "match_count": len(all_matches),
            }
        except Exception as e:
            logger.error(f"Error in hunt_iocs: {e}")
            return {"error": str(e)}

    def _hunt_anomalies(self, pcap_path: str, baseline_name: str | None = None) -> dict[str, Any]:
        """Internal implementation of hunt_anomalies."""
        try:
            if not Path(pcap_path).exists():
                return {"error": f"PCAP file not found: {pcap_path}"}

            # Load baseline if specified
            baseline = None
            if baseline_name:
                from src.wireshark.baseline.baseline_store import BaselineStore

                store = BaselineStore()
                baseline = store.load(baseline_name)

            # Create anomaly detector with baseline
            from src.wireshark.hunting.anomaly_detector import AnomalyDetector

            detector = AnomalyDetector(baseline=baseline)

            all_anomalies = []

            # Extract port statistics and check for port anomalies
            port_cmd = [self.executor.tshark_path, "-r", pcap_path, "-q", "-z", "conv,tcp"]
            returncode, stdout, _ = self.executor.execute(port_cmd, timeout=120)

            if returncode == 0 and stdout:
                # Parse port info and check for anomalies
                from collections import Counter

                port_counts = Counter()
                for line in stdout.split("\n"):
                    if ":" in line and "<->" in line:
                        parts = line.split()
                        for part in parts:
                            if ":" in part and part.count(":") == 1:
                                try:
                                    port = int(part.split(":")[1])
                                    port_counts[port] += 1
                                except (ValueError, IndexError):
                                    pass

                for port, count in port_counts.items():
                    port_anomalies = detector.check_port_anomaly(port=port, protocol="tcp", occurrence_count=count)
                    for anomaly in port_anomalies:
                        all_anomalies.append(
                            {
                                "type": anomaly.type,
                                "severity": anomaly.severity,
                                "description": anomaly.description,
                                "port": anomaly.port,
                                "confidence": anomaly.confidence,
                            }
                        )

            # Extract DNS queries and check for DNS anomalies
            dns_cmd = [
                self.executor.tshark_path,
                "-r",
                pcap_path,
                "-Y",
                "dns.flags.response == 0",
                "-T",
                "fields",
                "-e",
                "ip.src",
                "-e",
                "dns.qry.name",
                "-e",
                "dns.qry.type",
            ]
            returncode, stdout, _ = self.executor.execute(dns_cmd, timeout=120)

            if returncode == 0 and stdout:
                for line in stdout.strip().split("\n"):
                    if line:
                        parts = line.split("\t")
                        if len(parts) >= 2:
                            src_ip = parts[0] if parts[0] else "unknown"
                            query_name = parts[1] if len(parts) > 1 else ""
                            query_type = parts[2] if len(parts) > 2 else "A"

                            dns_anomalies = detector.check_dns_anomaly(
                                query_name=query_name, query_type=query_type, response_code=None, src_ip=src_ip
                            )
                            for anomaly in dns_anomalies:
                                all_anomalies.append(
                                    {
                                        "type": anomaly.type,
                                        "severity": anomaly.severity,
                                        "description": anomaly.description,
                                        "confidence": anomaly.confidence,
                                    }
                                )

            # Generate summary
            summary = {
                "total_anomalies": len(all_anomalies),
                "by_severity": {},
                "by_type": {},
            }
            for anomaly in all_anomalies:
                sev = anomaly.get("severity", "unknown")
                summary["by_severity"][sev] = summary["by_severity"].get(sev, 0) + 1
                atype = anomaly.get("type", "unknown")
                summary["by_type"][atype] = summary["by_type"].get(atype, 0) + 1

            return {
                "pcap_path": pcap_path,
                "baseline_used": baseline_name,
                "anomalies": all_anomalies,
                "summary": summary,
            }
        except Exception as e:
            logger.error(f"Error in hunt_anomalies: {e}")
            return {"error": str(e)}

    def _track_sessions(
        self, pcap_path: str, protocol: str = "tcp", port_filter: list[int] | None = None
    ) -> dict[str, Any]:
        """Internal implementation of track_sessions."""
        try:
            if not Path(pcap_path).exists():
                return {"error": f"PCAP file not found: {pcap_path}"}

            sessions = self.session_tracker.track_from_pcap(
                pcap_path=pcap_path, protocol=protocol, executor=self.executor
            )

            # Apply port filter if specified
            if port_filter:
                sessions = self.session_tracker.filter_by_port(sessions, port_filter)

            summary = self.session_tracker.get_session_summary(sessions)

            return {
                "pcap_path": pcap_path,
                "protocol": protocol,
                "sessions": [
                    {
                        "stream_id": s.stream_id,
                        "src_ip": s.src_ip,
                        "dst_ip": s.dst_ip,
                        "src_port": s.src_port,
                        "dst_port": s.dst_port,
                        "packet_count": s.packet_count,
                        "total_bytes": s.byte_count,
                    }
                    for s in sessions[:50]  # Limit to 50 sessions in response
                ],
                "summary": summary,
            }
        except Exception as e:
            logger.error(f"Error in track_sessions: {e}")
            return {"error": str(e)}

    def _extract_objects(self, pcap_path: str, protocol: str = "http", store_files: bool = False) -> dict[str, Any]:
        """Internal implementation of extract_objects."""
        try:
            if not Path(pcap_path).exists():
                return {"error": f"PCAP file not found: {pcap_path}"}

            results = self.object_extractor.extract_from_pcap(
                pcap_path=pcap_path, protocols=[protocol], store_files=store_files
            )

            return {
                "pcap_path": pcap_path,
                "protocol": protocol,
                "total_objects": results.get("total_objects", 0),
                "objects": results.get("objects", []),
                "stored_locally": store_files,
            }
        except Exception as e:
            logger.error(f"Error in extract_objects: {e}")
            return {"error": str(e)}

    def _detect_beaconing(
        self, pcap_path: str, min_connections: int = 5, max_jitter_percent: float = 90.0
    ) -> dict[str, Any]:
        """Internal implementation of detect_beaconing."""
        try:
            if not Path(pcap_path).exists():
                return {"error": f"PCAP file not found: {pcap_path}"}

            # detect_from_pcap returns List[BeaconPattern]
            # Pass user thresholds directly so detection uses them
            filtered_patterns = self.beaconing_detector.detect_from_pcap(
                pcap_path=pcap_path,
                executor=self.executor,
                min_count=min_connections,
                max_jitter=max_jitter_percent,
            )

            # Convert BeaconPattern objects to dicts
            patterns = []
            for p in filtered_patterns:
                patterns.append(
                    {
                        "src_ip": p.source_ip,
                        "dst_ip": p.dest_ip,
                        "dst_port": p.dest_port,
                        "interval_mean": p.interval_mean_seconds,
                        "jitter_percent": p.jitter_percent,
                        "occurrence_count": p.occurrence_count,
                        "confidence": p.confidence,
                        "events": [
                            {"timestamp": ts.timestamp(), "src_ip": p.source_ip, "dst_ip": p.dest_ip}
                            for ts in p.timestamps[:20]  # Limit events
                        ],
                    }
                )

            # Generate timeline visualization
            timeline = ""
            if patterns:
                from src.wireshark.reporting.timeline_visualizer import (
                    TimelineVisualizer,
                )

                visualizer = TimelineVisualizer()
                timeline = visualizer.generate_beaconing_timeline(
                    beacon_events=patterns[0].get("events", []), target_ip=patterns[0].get("dst_ip", "unknown")
                )

            # Build summary
            summary = {
                "total_patterns": len(patterns),
                "high_confidence": len([p for p in patterns if p.get("confidence") == "HIGH"]),
                "medium_confidence": len([p for p in patterns if p.get("confidence") == "MEDIUM"]),
                "low_confidence": len([p for p in patterns if p.get("confidence") == "LOW"]),
            }

            return {
                "pcap_path": pcap_path,
                "beacons": patterns,
                "patterns": patterns,
                "timeline": timeline,
                "summary": summary,
            }
        except Exception as e:
            logger.error(f"Error in detect_beaconing: {e}")
            return {"error": str(e)}

    def _detect_lateral_movement(self, pcap_path: str, internal_only: bool = True) -> dict[str, Any]:
        """Internal implementation of detect_lateral_movement."""
        try:
            if not Path(pcap_path).exists():
                return {"error": f"PCAP file not found: {pcap_path}"}

            results = self.lateral_movement_detector.detect_from_pcap(pcap_path=pcap_path, executor=self.executor)

            return {
                "pcap_path": pcap_path,
                "findings": {
                    "smb": results.get("smb_findings", []),
                    "rdp": results.get("rdp_findings", []),
                    "winrm": results.get("winrm_findings", []),
                },
                "enumeration": results.get("enumeration_findings", []),
                "psexec_patterns": results.get("psexec_patterns", []),
                "summary": results.get("summary", {}),
            }
        except Exception as e:
            logger.error(f"Error in detect_lateral_movement: {e}")
            return {"error": str(e)}

    def _generate_iocs(self, pcap_path: str, min_confidence: int = 5) -> dict[str, Any]:
        """Internal implementation of generate_iocs."""
        try:
            if not Path(pcap_path).exists():
                return {"error": f"PCAP file not found: {pcap_path}"}

            # Run analysis to extract IoCs
            anomalies = self._hunt_anomalies(pcap_path)
            beaconing = self._detect_beaconing(pcap_path)
            lateral = self._detect_lateral_movement(pcap_path)

            iocs = []

            # Extract IPs from beaconing patterns
            confidence_map = {"HIGH": 9, "MEDIUM": 6, "LOW": 3}
            for pattern in beaconing.get("patterns", []):
                conf = pattern.get("confidence", 0)
                conf_int = confidence_map.get(conf, conf) if isinstance(conf, str) else conf
                if conf_int >= min_confidence:
                    iocs.append(
                        {
                            "type": "ip",
                            "value": pattern.get("dst_ip"),
                            "confidence": conf_int,
                            "source": "beaconing_detection",
                        }
                    )

            # Extract IPs from lateral movement
            for finding in lateral.get("findings", {}).get("smb", []):
                iocs.append(
                    {
                        "type": "ip",
                        "value": finding.get("dst_ip"),
                        "confidence": 7,
                        "source": "lateral_movement",
                    }
                )

            return {
                "pcap_path": pcap_path,
                "iocs": iocs,
                "total_iocs": len(iocs),
            }
        except Exception as e:
            logger.error(f"Error in generate_iocs: {e}")
            return {"error": str(e)}

    def _generate_report(
        self, pcap_path: str, findings: dict[str, Any] | None = None, investigation_id: str | None = None
    ) -> dict[str, Any]:
        """Internal implementation of generate_report."""
        try:
            # If no findings provided, run analysis
            if findings is None:
                findings = {
                    "beaconing": self._detect_beaconing(pcap_path).get("patterns", []),
                    "anomalies": self._hunt_anomalies(pcap_path).get("anomalies", []),
                    "lateral_movement": self._detect_lateral_movement(pcap_path).get("findings", {}).get("smb", []),
                    "iocs": self._generate_iocs(pcap_path).get("iocs", []),
                }

            report = self.report_generator.generate_report(
                pcap_path=pcap_path, findings=findings, investigation_id=investigation_id
            )

            return {
                "pcap_path": pcap_path,
                "investigation_id": investigation_id,
                "report": report,
            }
        except Exception as e:
            logger.error(f"Error in generate_report: {e}")
            return {"error": str(e)}

    def _decode_traffic(self, pcap_path: str, port: int, protocol: str) -> dict[str, Any]:
        """Internal implementation of decode_traffic."""
        try:
            if not Path(pcap_path).exists():
                return {"error": f"PCAP file not found: {pcap_path}"}

            # Use tshark with decode-as option
            result = self.executor.execute(
                pcap_path=pcap_path,
                display_filter=f"tcp.port == {port}",
                decode_as=f"tcp.port=={port},{protocol}",
                timeout=120,
            )

            return {
                "pcap_path": pcap_path,
                "port": port,
                "protocol": protocol,
                "decoded_packets": len(result.get("output", "").split("\n")),
                "output": result.get("output", "")[:5000],  # Limit output size
            }
        except Exception as e:
            logger.error(f"Error in decode_traffic: {e}")
            return {"error": str(e)}
