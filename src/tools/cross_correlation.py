"""Cross-correlation tools bridging SIEM and endpoint data.

These tools orchestrate between CrowdSentinel's Elasticsearch hunting tools
and Velociraptor's endpoint forensic tools to correlate IoCs across sources.
"""

import logging
import re
from typing import Any

from fastmcp import FastMCP

from src.storage.auto_capture import get_client
from src.storage.models import IoCType

logger = logging.getLogger(__name__)

# Only allow safe characters for IoC values injected into VQL regex params
_SAFE_IOC_RE = re.compile(r"^[\w.\-:/\\@]+$")


def _sanitize_ioc_for_vql(value: str) -> str:
    """Sanitize an IoC value for safe use in a VQL regex parameter.

    Returns the value if safe, raises ValueError otherwise.
    """
    if not _SAFE_IOC_RE.match(value):
        raise ValueError(f"IoC value contains unsafe characters for VQL: {value!r}")
    return re.escape(value)


class CrossCorrelationTools:
    """MCP tools for cross-correlating SIEM and endpoint forensic data."""

    def __init__(self):
        self.logger = logger
        self._vr_client = None

    def _get_vr_client(self):
        """Lazily get the Velociraptor client."""
        if self._vr_client is not None:
            return self._vr_client

        import os

        config_path = os.environ.get("VELOCIRAPTOR_API_CONFIG")
        if not config_path:
            raise RuntimeError("VELOCIRAPTOR_API_CONFIG not set — cross-correlation unavailable")

        from src.clients.velociraptor_client import VelociraptorClient

        self._vr_client = VelociraptorClient(config_path)
        return self._vr_client

    def register_tools(self, mcp: FastMCP):
        tools_instance = self

        @mcp.tool()
        async def correlate_siem_with_endpoint(
            client_id: str,
            investigation_id: str | None = None,
        ) -> dict:
            """
            Cross-correlate SIEM IoCs with live endpoint data via Velociraptor.

            Takes IoCs from the active investigation (IPs, processes, services)
            and automatically runs matching Velociraptor queries to validate
            whether those indicators are present on the target endpoint.

            Args:
                client_id: Velociraptor client ID of the endpoint to check.
                investigation_id: Investigation to pull IoCs from (uses active if None).

            Returns:
                Correlation results showing which SIEM IoCs were confirmed on the endpoint.
            """
            state_client = get_client()
            investigation = state_client._get_investigation(investigation_id)
            if not investigation:
                return {"error": "No active investigation. Use create_investigation() first."}

            vr_client = tools_instance._get_vr_client()
            iocs = investigation.iocs.iocs
            if not iocs:
                return {"error": "No IoCs in investigation to correlate."}

            correlations: list[dict[str, Any]] = []
            errors: list[str] = []
            checked = {"processes": 0, "ips": 0, "services": 0}

            process_iocs = [ioc for ioc in iocs if ioc.type == IoCType.PROCESS]
            ip_iocs = [ioc for ioc in iocs if ioc.type == IoCType.IP]
            service_iocs = [ioc for ioc in iocs if ioc.type == IoCType.SERVICE]

            # Check suspicious processes
            for ioc in process_iocs[:20]:
                try:
                    safe_value = _sanitize_ioc_for_vql(ioc.value)
                    results = await vr_client.collect_realtime(
                        client_id,
                        "Windows.System.Pslist",
                        f"ProcessRegex='{safe_value}'",
                        "Pid,Name,Exe,CommandLine,Username",
                    )
                    checked["processes"] += 1
                    if results:
                        correlations.append({
                            "ioc_type": "process",
                            "ioc_value": ioc.value,
                            "confirmed": True,
                            "endpoint_matches": len(results),
                            "details": results[:5],
                            "pyramid_priority": ioc.pyramid_priority,
                        })
                except ValueError as e:
                    logger.warning("Skipping IoC %s: %s", ioc.value, e)
                except RuntimeError as e:
                    errors.append(f"gRPC error checking process {ioc.value}: {e}")
                    logger.error("gRPC error checking process %s: %s", ioc.value, e)
                    break  # Connection-level error — stop trying

            # Check suspicious IPs in network connections
            for ioc in ip_iocs[:20]:
                try:
                    safe_value = _sanitize_ioc_for_vql(ioc.value)
                    results = await vr_client.collect_realtime(
                        client_id,
                        "Windows.Network.NetstatEnriched/Netstat",
                        f"IPRegex='{safe_value}'",
                        "Pid,Name,Status,Raddr,Rport,Laddr,Lport",
                    )
                    checked["ips"] += 1
                    if results:
                        correlations.append({
                            "ioc_type": "ip",
                            "ioc_value": ioc.value,
                            "confirmed": True,
                            "endpoint_matches": len(results),
                            "details": results[:5],
                            "pyramid_priority": ioc.pyramid_priority,
                        })
                except ValueError as e:
                    logger.warning("Skipping IoC %s: %s", ioc.value, e)
                except RuntimeError as e:
                    errors.append(f"gRPC error checking IP {ioc.value}: {e}")
                    logger.error("gRPC error checking IP %s: %s", ioc.value, e)
                    break

            # Check suspicious services (no regex param — filter client-side)
            for ioc in service_iocs[:10]:
                try:
                    results = await vr_client.collect_realtime(
                        client_id,
                        "Windows.System.Services",
                        "",
                        "DisplayName,AbsoluteExePath,UserAccount,HashServiceExe",
                    )
                    checked["services"] += 1
                    matching = [r for r in results if ioc.value.lower() in str(r).lower()]
                    if matching:
                        correlations.append({
                            "ioc_type": "service",
                            "ioc_value": ioc.value,
                            "confirmed": True,
                            "endpoint_matches": len(matching),
                            "details": matching[:5],
                            "pyramid_priority": ioc.pyramid_priority,
                        })
                except RuntimeError as e:
                    errors.append(f"gRPC error checking service {ioc.value}: {e}")
                    logger.error("gRPC error checking service %s: %s", ioc.value, e)
                    break

            confirmed = [c for c in correlations if c["confirmed"]]
            result = {
                "investigation_id": investigation.manifest.id,
                "client_id": client_id,
                "total_iocs_checked": sum(checked.values()),
                "checks_by_type": checked,
                "confirmed_on_endpoint": len(confirmed),
                "correlations": correlations,
                "severity": "critical" if len(confirmed) > 5 else "high" if confirmed else "low",
                "recommendation": (
                    "Multiple SIEM IoCs confirmed on endpoint — immediate containment recommended"
                    if len(confirmed) > 5
                    else "IoCs confirmed on endpoint — continue investigation"
                    if confirmed
                    else "No SIEM IoCs confirmed on this endpoint"
                ),
            }
            if errors:
                result["errors"] = errors
            return result

        @mcp.tool()
        async def endpoint_to_siem_pivot(
            client_id: str,
            artifact_type: str = "prefetch",
            search_index: str = "winlogbeat-*",
            timeframe_minutes: int = 1440,
        ) -> dict:
            """
            Collect an endpoint artifact, extract IoCs, then search SIEM for those IoCs across all hosts.

            This is the reverse of correlate_siem_with_endpoint — it starts from
            endpoint forensics and pivots to SIEM to find the same indicators on
            other machines (lateral movement detection).

            Args:
                client_id: Velociraptor client ID to collect from.
                artifact_type: Type of artifact — 'prefetch', 'netstat', 'services', 'amcache'.
                search_index: Elasticsearch index to search in SIEM.
                timeframe_minutes: How far back to search in SIEM (default: 24 hours).

            Returns:
                Pivot results showing which endpoint IoCs appear across SIEM data.
            """
            vr_client = tools_instance._get_vr_client()

            artifact_map = {
                "prefetch": ("Windows.Forensics.Prefetch", "Binary,Hash,LastRunTimes,RunCount"),
                "netstat": ("Windows.Network.NetstatEnriched/Netstat", "Raddr,Rport,Name,Path"),
                "services": ("Windows.System.Services", "AbsoluteExePath,HashServiceExe,DisplayName"),
                "amcache": ("Windows.Detection.Amcache", "FullPath,SHA1,Publisher,LastRunTime"),
            }

            if artifact_type not in artifact_map:
                return {"error": f"Unknown artifact_type: {artifact_type}. Use: {list(artifact_map.keys())}"}

            artifact_name, fields = artifact_map[artifact_type]
            endpoint_results = await vr_client.collect_realtime(client_id, artifact_name, "", fields)

            if not endpoint_results:
                return {"error": f"No results from {artifact_type} collection on {client_id}"}

            # Extract pivot-worthy IoCs from endpoint results
            pivot_iocs: list[dict[str, str]] = []
            for result in endpoint_results[:50]:
                if artifact_type == "prefetch":
                    binary = result.get("Binary", "")
                    if binary and not binary.lower().startswith("c:\\windows\\system32"):
                        pivot_iocs.append({"type": "process", "value": binary.split("\\")[-1]})
                elif artifact_type == "netstat":
                    raddr = result.get("Raddr", "")
                    if raddr and raddr not in ("0.0.0.0", "127.0.0.1", "::1", "::", ""):
                        pivot_iocs.append({"type": "ip", "value": raddr})
                elif artifact_type == "amcache":
                    sha1 = result.get("SHA1", "")
                    if sha1:
                        pivot_iocs.append({"type": "hash", "value": sha1})
                elif artifact_type == "services":
                    exe_hash = result.get("HashServiceExe", "")
                    if exe_hash:
                        pivot_iocs.append({"type": "hash", "value": exe_hash})

            # Deduplicate
            seen: set[str] = set()
            unique_iocs: list[dict[str, str]] = []
            for ioc in pivot_iocs:
                key = f"{ioc['type']}:{ioc['value']}"
                if key not in seen:
                    seen.add(key)
                    unique_iocs.append(ioc)

            return {
                "source_client_id": client_id,
                "artifact_type": artifact_type,
                "endpoint_results_count": len(endpoint_results),
                "pivot_iocs_extracted": len(unique_iocs),
                "pivot_iocs": unique_iocs[:30],
                "search_index": search_index,
                "timeframe_minutes": timeframe_minutes,
                "next_step": (
                    "Use hunt_for_ioc() with each pivot IoC to search SIEM for lateral movement. "
                    "Focus on IoCs appearing on multiple hosts."
                ),
            }

        @mcp.tool()
        def build_unified_timeline(investigation_id: str | None = None) -> dict:
            """
            Build a unified chronological timeline merging events from all sources.

            Combines timeline events from Elasticsearch, Velociraptor, Chainsaw,
            and Wireshark into a single chronological view for the investigation.

            Args:
                investigation_id: Investigation to build timeline for (uses active if None).

            Returns:
                Unified timeline with events sorted chronologically and grouped by source.
            """
            state_client = get_client()
            investigation = state_client._get_investigation(investigation_id)
            if not investigation:
                return {"error": "No active investigation. Use create_investigation() first."}

            timeline = investigation.timeline
            if not timeline:
                return {
                    "investigation_id": investigation.manifest.id,
                    "total_events": 0,
                    "message": "No timeline events yet. Run hunting/collection tools first.",
                }

            by_source: dict[str, int] = {}
            by_severity: dict[str, int] = {}
            hosts_seen: set[str] = set()
            users_seen: set[str] = set()
            mitre_seen: set[str] = set()

            events_serialized: list[dict[str, Any]] = []
            for event in timeline:
                source_key = event.source.value if hasattr(event.source, "value") else str(event.source)
                by_source[source_key] = by_source.get(source_key, 0) + 1

                severity_key = event.severity.value if hasattr(event.severity, "value") else str(event.severity)
                by_severity[severity_key] = by_severity.get(severity_key, 0) + 1

                if event.host:
                    hosts_seen.add(event.host)
                if event.user:
                    users_seen.add(event.user)
                if event.mitre_technique:
                    mitre_seen.add(event.mitre_technique)

                events_serialized.append({
                    "timestamp": event.timestamp.isoformat(),
                    "source": source_key,
                    "tool": event.tool,
                    "event_type": event.event_type,
                    "summary": event.summary,
                    "severity": severity_key,
                    "host": event.host,
                    "user": event.user,
                    "mitre_technique": event.mitre_technique,
                })

            first_event = timeline[0].timestamp
            last_event = timeline[-1].timestamp
            span_seconds = (last_event - first_event).total_seconds()

            return {
                "investigation_id": investigation.manifest.id,
                "investigation_name": investigation.manifest.name,
                "total_events": len(timeline),
                "time_span": {
                    "first_event": first_event.isoformat(),
                    "last_event": last_event.isoformat(),
                    "duration_seconds": span_seconds,
                    "duration_human": (
                        f"{int(span_seconds // 3600)}h {int((span_seconds % 3600) // 60)}m"
                        if span_seconds > 3600
                        else f"{int(span_seconds // 60)}m {int(span_seconds % 60)}s"
                    ),
                },
                "by_source": by_source,
                "by_severity": by_severity,
                "unique_hosts": list(hosts_seen),
                "unique_users": list(users_seen),
                "mitre_techniques": list(mitre_seen),
                "events": events_serialized,
            }
