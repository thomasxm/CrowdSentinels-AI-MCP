"""Smart extraction engine for token-efficient IoC and event extraction."""

import logging
from datetime import datetime
from typing import Any

from src.storage.models import (
    IoC,
    IoCSource,
    IoCType,
    Severity,
    SourceFindings,
    SourceType,
    TimelineEvent,
)

logger = logging.getLogger(__name__)


# Pyramid of Pain priority mapping
PYRAMID_PRIORITY = {
    IoCType.HASH: 1,  # Trivial - easily changed
    IoCType.IP: 2,  # Easy - can be changed quickly
    IoCType.DOMAIN: 3,  # Simple - takes some effort
    IoCType.URL: 3,
    IoCType.EMAIL: 3,
    IoCType.USER: 4,  # Annoying - network artifacts
    IoCType.HOSTNAME: 4,
    IoCType.FILE_PATH: 4,
    IoCType.REGISTRY_KEY: 4,
    IoCType.SERVICE: 4,
    IoCType.SCHEDULED_TASK: 4,
    IoCType.PROCESS: 5,  # Challenging - tools
    IoCType.COMMANDLINE: 6,  # Tough - TTPs
    IoCType.OTHER: 3,
}

# MITRE ATT&CK mapping for Windows Event IDs
MITRE_EVENT_MAPPING = {
    "4624": {"technique": "T1078", "tactic": "Defense Evasion", "name": "Valid Accounts"},
    "4625": {"technique": "T1110", "tactic": "Credential Access", "name": "Brute Force"},
    "4672": {"technique": "T1078.002", "tactic": "Privilege Escalation", "name": "Admin Account"},
    "4688": {"technique": "T1059", "tactic": "Execution", "name": "Command Interpreter"},
    "4697": {"technique": "T1543.003", "tactic": "Persistence", "name": "Windows Service"},
    "4698": {"technique": "T1053.005", "tactic": "Persistence", "name": "Scheduled Task"},
    "4720": {"technique": "T1136.001", "tactic": "Persistence", "name": "Create Account"},
    "4732": {"technique": "T1098", "tactic": "Persistence", "name": "Account Manipulation"},
    "5140": {"technique": "T1021.002", "tactic": "Lateral Movement", "name": "SMB Shares"},
    "1": {"technique": "T1059", "tactic": "Execution", "name": "Process Creation (Sysmon)"},
    "3": {"technique": "T1071", "tactic": "Command and Control", "name": "Network Connection"},
    "7": {"technique": "T1055", "tactic": "Defense Evasion", "name": "Image Loaded"},
    "11": {"technique": "T1105", "tactic": "Command and Control", "name": "File Created"},
    "13": {"technique": "T1112", "tactic": "Defense Evasion", "name": "Registry Value Set"},
}


class SmartExtractor:
    """Extracts IoCs and events efficiently to minimize storage and tokens."""

    def __init__(self, max_iocs: int = 1000, max_events: int = 100):
        """Initialize the extractor."""
        self.max_iocs = max_iocs
        self.max_events = max_events
        self._seen_values: set[str] = set()

    def reset(self) -> None:
        """Reset the seen values cache."""
        self._seen_values = set()

    def extract_iocs_from_elasticsearch(
        self,
        results: dict[str, Any],
        source_tool: str = "elasticsearch",
        investigation_id: str | None = None,
    ) -> list[IoC]:
        """
        Extract IoCs from Elasticsearch search results.

        Args:
            results: Elasticsearch search results (handles both raw ES and MCP tool formats)
            source_tool: Name of the tool that ran the query
            investigation_id: Associated investigation ID

        Returns:
            List of extracted IoCs
        """
        iocs = []

        # Handle different result formats:
        # 1. Standard ES format: {"hits": {"hits": [...]}}
        # 2. MCP tool format: {"events": [...]} or {"response": {"events": [...]}}
        # 3. Hunt results: {"findings": {...}}
        # 4. Truncated string response (when response was too large)

        hits = []

        # Handle response wrapper (from limit_response_size)
        if "response" in results:
            response = results["response"]
            # Response might be a truncated string when results were too large
            if isinstance(response, str):
                # Try to parse as Python dict literal
                try:
                    import ast

                    response = ast.literal_eval(response)
                except (ValueError, SyntaxError):
                    logger.warning("Could not parse truncated response string")
                    response = {}

            if isinstance(response, dict):
                # MCP tool format with events
                if "events" in response:
                    hits = response.get("events", [])
                # Standard ES format
                elif "hits" in response and isinstance(response.get("hits"), dict):
                    hits = response.get("hits", {}).get("hits", [])

        # Try standard ES format at top level
        if not hits and "hits" in results and isinstance(results.get("hits"), dict):
            hits = results.get("hits", {}).get("hits", [])
        # Direct events array at top level
        elif not hits and "events" in results:
            hits = results.get("events", [])
        # Hunt findings format
        elif not hits and "findings" in results:
            for attack_type, data in results.get("findings", {}).items():
                if isinstance(data, dict) and "events" in data:
                    hits.extend(data.get("events", []))

        for hit in hits:
            # Standard ES format has _source wrapper, MCP tools return events directly
            if "_source" in hit:
                source = hit.get("_source", {})
            else:
                # MCP tools return events without _source wrapper
                source = hit
            extracted = self._extract_from_event(source, SourceType.ELASTICSEARCH, source_tool, investigation_id)
            iocs.extend(extracted)

        # Deduplicate and prioritize
        return self._deduplicate_and_prioritize(iocs)

    def extract_iocs_from_chainsaw(
        self,
        results: dict[str, Any],
        source_tool: str = "chainsaw",
        investigation_id: str | None = None,
    ) -> list[IoC]:
        """
        Extract IoCs from Chainsaw results.

        Args:
            results: Chainsaw hunt results
            source_tool: Name of the tool
            investigation_id: Associated investigation ID

        Returns:
            List of extracted IoCs
        """
        iocs = []
        detections = results.get("detections", [])

        for detection in detections:
            # Extract from detection data
            event_data = detection.get("event", {}) or detection.get("data", {})
            extracted = self._extract_from_event(event_data, SourceType.CHAINSAW, source_tool, investigation_id)

            # Add rule-specific context
            rule_name = detection.get("rule", {}).get("name", "")
            for ioc in extracted:
                if rule_name:
                    ioc.tags.append(f"rule:{rule_name}")

            iocs.extend(extracted)

        return self._deduplicate_and_prioritize(iocs)

    def extract_iocs_from_wireshark(
        self,
        results: dict[str, Any],
        source_tool: str = "wireshark",
        investigation_id: str | None = None,
    ) -> list[IoC]:
        """
        Extract IoCs from Wireshark/tshark results.

        Args:
            results: Wireshark analysis results
            source_tool: Name of the tool
            investigation_id: Associated investigation ID

        Returns:
            List of extracted IoCs
        """
        iocs = []
        packets = results.get("packets", []) or results.get("flows", [])

        for packet in packets:
            # Extract network-specific IoCs
            if "ip.src" in packet or "source_ip" in packet:
                ip = packet.get("ip.src") or packet.get("source_ip")
                if ip and self._is_valid_ioc(ip, IoCType.IP):
                    iocs.append(
                        self._create_ioc(
                            ip, IoCType.IP, SourceType.WIRESHARK, source_tool, investigation_id, {"direction": "source"}
                        )
                    )

            if "ip.dst" in packet or "dest_ip" in packet:
                ip = packet.get("ip.dst") or packet.get("dest_ip")
                if ip and self._is_valid_ioc(ip, IoCType.IP):
                    iocs.append(
                        self._create_ioc(
                            ip,
                            IoCType.IP,
                            SourceType.WIRESHARK,
                            source_tool,
                            investigation_id,
                            {"direction": "destination"},
                        )
                    )

            if "dns.qry.name" in packet:
                domain = packet.get("dns.qry.name")
                if domain and self._is_valid_ioc(domain, IoCType.DOMAIN):
                    iocs.append(
                        self._create_ioc(
                            domain,
                            IoCType.DOMAIN,
                            SourceType.WIRESHARK,
                            source_tool,
                            investigation_id,
                            {"query_type": "dns"},
                        )
                    )

        return self._deduplicate_and_prioritize(iocs)

    def extract_iocs_from_velociraptor(
        self,
        results: dict[str, Any],
        source_tool: str = "velociraptor",
        investigation_id: str | None = None,
    ) -> list[IoC]:
        """
        Extract IoCs from Velociraptor artifact collection results.

        Velociraptor results arrive as a list of dicts (from VQL queries) or
        a dict with an "events" key wrapping that list. Field names vary by
        artifact type, so we map common Velociraptor fields to IoC types.

        Args:
            results: Velociraptor collection results
            source_tool: Name of the tool that ran the query
            investigation_id: Associated investigation ID

        Returns:
            List of extracted IoCs
        """
        iocs: list[IoC] = []

        # Normalize: results may be a list or a dict wrapping a list
        events: list[dict[str, Any]] = []
        if isinstance(results, list):
            events = results
        elif isinstance(results, dict):
            if "events" in results:
                events = results.get("events", [])
            elif "response" in results and isinstance(results["response"], list):
                events = results["response"]
            else:
                # Single result dict
                events = [results]

        # Field mapping: Velociraptor field -> (IoCType, context_tag)
        vr_field_map: list[tuple[list[str], IoCType, str]] = [
            # Process fields
            (["Name", "Exe", "Binary", "process.name"], IoCType.PROCESS, "process"),
            # Command line fields
            (["CommandLine", "command_line", "ExpandedCommand"], IoCType.COMMANDLINE, "commandline"),
            # File path fields
            (["FullPath", "OSPath", "Path", "AbsoluteExePath", "DownloadedFilePath"], IoCType.FILE_PATH, "filepath"),
            # IP address fields
            (["Laddr", "Raddr"], IoCType.IP, "network"),
            # Hash fields
            (["SHA1", "Hash", "FileHash", "HashServiceExe", "HashServiceDll", "MD5"], IoCType.HASH, "hash"),
            # User fields
            (["Username", "User", "UserId", "UserAccount"], IoCType.USER, "user"),
            # Hostname fields
            (["Hostname", "Fqdn"], IoCType.HOSTNAME, "host"),
            # Service fields
            (["ServiceDll", "DisplayName"], IoCType.SERVICE, "service"),
            # URL fields
            (["HostUrl", "ReferrerUrl"], IoCType.URL, "url"),
            # Registry key fields
            (["Key", "KeyPath", "MountPoint"], IoCType.REGISTRY_KEY, "registry"),
        ]

        for event in events:
            if not isinstance(event, dict):
                continue

            for fields, ioc_type, context_tag in vr_field_map:
                for field in fields:
                    value = event.get(field)
                    if not value or not isinstance(value, str):
                        continue
                    value = value.strip()
                    if not value:
                        continue

                    # Validate value for the target IoC type
                    if not self._is_valid_ioc(value, ioc_type):
                        continue

                    iocs.append(
                        self._create_ioc(
                            value,
                            ioc_type,
                            SourceType.VELOCIRAPTOR,
                            source_tool,
                            investigation_id,
                            {"field": field, "artifact_type": context_tag},
                        )
                    )

        return self._deduplicate_and_prioritize(iocs)

    def _extract_from_event(
        self,
        event: dict[str, Any],
        source_type: SourceType,
        source_tool: str,
        investigation_id: str | None,
    ) -> list[IoC]:
        """Extract IoCs from a single event."""
        iocs = []

        # IP addresses
        for ip_field in [
            "source.ip",
            "destination.ip",
            "client.ip",
            "server.ip",
            "host.ip",
            "src_ip",
            "dst_ip",
            "remote_ip",
            "IpAddress",
            "winlog.event_data.IpAddress",
            "related.ip",
        ]:
            ip_value = self._get_nested_list(event, ip_field)
            if ip_value:
                # Handle both single values and lists
                ip_list = ip_value if isinstance(ip_value, list) else [ip_value]
                for ip in ip_list:
                    if ip and self._is_valid_ioc(str(ip), IoCType.IP):
                        iocs.append(
                            self._create_ioc(
                                str(ip), IoCType.IP, source_type, source_tool, investigation_id, {"field": ip_field}
                            )
                        )

        # Usernames
        for user_field in [
            "user.name",
            "winlog.event_data.TargetUserName",
            "winlog.event_data.SubjectUserName",
            "winlog.event_data.User",
            "related.user",
            "User",
            "user",
        ]:
            user = self._get_nested(event, user_field)
            if user and self._is_valid_ioc(user, IoCType.USER):
                iocs.append(
                    self._create_ioc(
                        user, IoCType.USER, source_type, source_tool, investigation_id, {"field": user_field}
                    )
                )

        # Hostnames
        for host_field in ["host.name", "host.hostname", "ComputerName", "winlog.computer_name", "hostname"]:
            host = self._get_nested(event, host_field)
            if host and self._is_valid_ioc(host, IoCType.HOSTNAME):
                iocs.append(
                    self._create_ioc(
                        host, IoCType.HOSTNAME, source_type, source_tool, investigation_id, {"field": host_field}
                    )
                )

        # Processes
        for proc_field in [
            "process.name",
            "winlog.event_data.NewProcessName",
            "winlog.event_data.Image",
            "process.executable",
        ]:
            proc = self._get_nested(event, proc_field)
            if proc and self._is_valid_ioc(proc, IoCType.PROCESS):
                iocs.append(
                    self._create_ioc(
                        proc, IoCType.PROCESS, source_type, source_tool, investigation_id, {"field": proc_field}
                    )
                )

        # Command lines (TTPs - highest priority)
        for cmd_field in [
            "process.command_line",
            "winlog.event_data.CommandLine",
            "winlog.event_data.ParentCommandLine",
        ]:
            cmd = self._get_nested(event, cmd_field)
            if cmd and self._is_valid_ioc(cmd, IoCType.COMMANDLINE):
                iocs.append(
                    self._create_ioc(
                        cmd, IoCType.COMMANDLINE, source_type, source_tool, investigation_id, {"field": cmd_field}
                    )
                )

        # Hashes
        for hash_field in ["file.hash.sha256", "file.hash.md5", "file.hash.sha1", "winlog.event_data.Hashes"]:
            hash_val = self._get_nested(event, hash_field)
            if hash_val and self._is_valid_ioc(hash_val, IoCType.HASH):
                iocs.append(
                    self._create_ioc(
                        hash_val, IoCType.HASH, source_type, source_tool, investigation_id, {"field": hash_field}
                    )
                )

        # File paths
        for path_field in ["file.path", "winlog.event_data.TargetFilename", "process.executable"]:
            path = self._get_nested(event, path_field)
            if path and self._is_valid_ioc(path, IoCType.FILE_PATH):
                iocs.append(
                    self._create_ioc(
                        path, IoCType.FILE_PATH, source_type, source_tool, investigation_id, {"field": path_field}
                    )
                )

        # Registry keys
        for reg_field in ["registry.path", "winlog.event_data.TargetObject"]:
            reg = self._get_nested(event, reg_field)
            if reg and self._is_valid_ioc(reg, IoCType.REGISTRY_KEY):
                iocs.append(
                    self._create_ioc(
                        reg, IoCType.REGISTRY_KEY, source_type, source_tool, investigation_id, {"field": reg_field}
                    )
                )

        return iocs

    def _create_ioc(
        self,
        value: str,
        ioc_type: IoCType,
        source_type: SourceType,
        source_tool: str,
        investigation_id: str | None,
        context: dict[str, Any],
    ) -> IoC:
        """Create an IoC with source tracking."""
        source = IoCSource(
            tool=source_tool,
            source_type=source_type,
            investigation_id=investigation_id,
        )

        # Get MITRE techniques if applicable
        mitre_techniques = []
        event_code = context.get("event_code")
        if event_code and str(event_code) in MITRE_EVENT_MAPPING:
            mapping = MITRE_EVENT_MAPPING[str(event_code)]
            mitre_techniques.append(mapping["technique"])

        return IoC(
            type=ioc_type,
            value=value,
            pyramid_priority=PYRAMID_PRIORITY.get(ioc_type, 3),
            sources=[source],
            context=context,
            mitre_techniques=mitre_techniques,
        )

    def _is_valid_ioc(self, value: Any, ioc_type: IoCType) -> bool:
        """Check if a value is a valid IoC."""
        if not value or not isinstance(value, str):
            return False

        value = value.strip()
        if not value or len(value) < 2:
            return False

        # Skip system/default values
        skip_values = {
            "SYSTEM",
            "LOCAL SERVICE",
            "NETWORK SERVICE",
            "-",
            "N/A",
            "localhost",
            "127.0.0.1",
            "::1",
            "0.0.0.0",
        }
        if value.upper() in skip_values:
            return False

        # Type-specific validation
        if ioc_type == IoCType.IP:
            # Basic IP validation
            parts = value.split(".")
            if len(parts) != 4:
                return False
            try:
                return all(0 <= int(p) <= 255 for p in parts)
            except ValueError:
                return False

        if ioc_type == IoCType.USER:
            # Skip machine accounts and common system accounts
            if value.endswith("$") or value.upper() in skip_values:
                return False

        if ioc_type == IoCType.COMMANDLINE:
            # Must have some content
            return len(value) > 5

        return True

    def _get_nested(self, data: dict, path: str) -> str | None:
        """Get a nested value from a dictionary using dot notation.

        Handles both flat keys (e.g., "source.ip" as a direct key) and
        nested structures (e.g., {"source": {"ip": "1.2.3.4"}}).
        """
        if not isinstance(data, dict):
            return None

        # First try flat key (e.g., "source.ip" as a direct key)
        if path in data:
            value = data[path]
            if isinstance(value, list):
                return str(value[0]) if value else None
            return str(value) if value is not None else None

        # Then try nested access
        keys = path.split(".")
        value = data
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return None
        if isinstance(value, list):
            return str(value[0]) if value else None
        return str(value) if value is not None else None

    def _get_nested_list(self, data: dict, path: str) -> Any | None:
        """Get a nested value preserving lists.

        Similar to _get_nested but preserves list values for fields that
        can contain multiple values (e.g., host.ip).
        """
        if not isinstance(data, dict):
            return None

        # First try flat key
        if path in data:
            return data[path]

        # Then try nested access
        keys = path.split(".")
        value = data
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return None
        return value

    def _deduplicate_and_prioritize(self, iocs: list[IoC]) -> list[IoC]:
        """Deduplicate IoCs and sort by priority."""
        # Deduplicate by type+value
        unique: dict[str, IoC] = {}

        for ioc in iocs:
            key = f"{ioc.type.value}:{ioc.value}"
            if key in unique:
                unique[key].merge_with(ioc)
            else:
                unique[key] = ioc

        # Sort by priority (highest first) and limit
        sorted_iocs = sorted(unique.values(), key=lambda x: (x.pyramid_priority, x.total_occurrences), reverse=True)

        return sorted_iocs[: self.max_iocs]

    def summarize_events(
        self,
        events: list[dict[str, Any]],
        source_type: SourceType,
        source_tool: str,
    ) -> SourceFindings:
        """
        Create a summarized findings object from events.

        Args:
            events: List of events
            source_type: Source type
            source_tool: Tool name

        Returns:
            Summarized findings
        """
        # Extract key information
        event_types: dict[str, int] = {}
        hosts: set[str] = set()
        users: set[str] = set()
        mitre_techniques: set[str] = set()
        key_findings: list[str] = []

        for event in events:
            # Count event types
            event_code = self._get_nested(event, "event.code") or self._get_nested(event, "winlog.event_id")
            if event_code:
                event_types[str(event_code)] = event_types.get(str(event_code), 0) + 1

                # Map to MITRE
                if str(event_code) in MITRE_EVENT_MAPPING:
                    mitre_techniques.add(MITRE_EVENT_MAPPING[str(event_code)]["technique"])

            # Collect hosts
            host = self._get_nested(event, "host.name") or self._get_nested(event, "winlog.computer_name")
            if host:
                hosts.add(host)

            # Collect users
            user = self._get_nested(event, "user.name") or self._get_nested(event, "winlog.event_data.TargetUserName")
            if user and user.upper() not in {"SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE"}:
                users.add(user)

        # Generate key findings
        if len(hosts) > 1:
            key_findings.append(f"Activity detected across {len(hosts)} hosts")
        if len(users) > 3:
            key_findings.append(f"Multiple users involved: {len(users)} accounts")
        if mitre_techniques:
            key_findings.append(f"MITRE techniques: {', '.join(sorted(mitre_techniques))}")

        # Add event type insights
        for event_code, count in sorted(event_types.items(), key=lambda x: x[1], reverse=True)[:5]:
            if str(event_code) in MITRE_EVENT_MAPPING:
                mapping = MITRE_EVENT_MAPPING[str(event_code)]
                key_findings.append(f"Event {event_code} ({mapping['name']}): {count} occurrences")

        return SourceFindings(
            source=source_type,
            tool=source_tool,
            total_events=len(events),
            summary={
                "event_types": event_types,
                "unique_hosts": len(hosts),
                "unique_users": len(users),
                "hosts": list(hosts)[:10],  # Keep first 10
                "users": list(users)[:10],
            },
            key_findings=key_findings[:20],  # Keep top 20 findings
            iocs_extracted=0,  # Will be updated after IoC extraction
            events_kept=min(len(events), self.max_events),
            mitre_techniques=list(mitre_techniques),
        )

    def extract_timeline_events(
        self,
        events: list[dict[str, Any]],
        source_type: SourceType,
        source_tool: str,
        max_events: int | None = None,
    ) -> list[TimelineEvent]:
        """
        Extract significant events for the timeline.

        Args:
            events: List of raw events
            source_type: Source type
            source_tool: Tool name
            max_events: Maximum events to keep

        Returns:
            List of timeline events
        """
        max_events = max_events or self.max_events
        timeline = []

        for event in events:
            # Get timestamp
            timestamp_str = self._get_nested(event, "@timestamp") or self._get_nested(event, "timestamp")
            if not timestamp_str:
                continue

            try:
                if isinstance(timestamp_str, str):
                    # Handle various timestamp formats
                    timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                else:
                    timestamp = datetime.utcnow()
            except ValueError:
                continue

            # Get event details
            event_code = (
                self._get_nested(event, "event.code") or self._get_nested(event, "winlog.event_id") or "unknown"
            )

            # Determine severity
            severity = Severity.INFO
            if str(event_code) in ["4625", "4672", "4697", "4698"]:
                severity = Severity.HIGH
            elif str(event_code) in ["4624", "4688"]:
                severity = Severity.MEDIUM

            # Build summary
            host = self._get_nested(event, "host.name") or "unknown"
            user = self._get_nested(event, "user.name") or self._get_nested(event, "winlog.event_data.TargetUserName")
            summary = f"Event {event_code}"
            if user:
                summary += f" by {user}"
            summary += f" on {host}"

            # Get MITRE technique
            mitre_technique = None
            if str(event_code) in MITRE_EVENT_MAPPING:
                mitre_technique = MITRE_EVENT_MAPPING[str(event_code)]["technique"]

            timeline_event = TimelineEvent(
                timestamp=timestamp,
                event_type=str(event_code),
                source=source_type,
                tool=source_tool,
                summary=summary,
                severity=severity,
                host=host,
                user=user,
                mitre_technique=mitre_technique,
                details={
                    "event_code": event_code,
                    "original_index": event.get("_index"),
                },
            )
            timeline.append(timeline_event)

        # Sort by timestamp and limit
        timeline.sort(key=lambda x: x.timestamp)
        return timeline[:max_events]

    def estimate_tokens(self, data: Any) -> int:
        """
        Estimate token count for data.

        Rough estimate: 1 token ≈ 4 characters
        """
        import json

        if isinstance(data, str):
            text = data
        else:
            text = json.dumps(data)
        return len(text) // 4
