"""MCP Tools for Investigation State Management.

These tools provide investigation lifecycle management with:
- Cross-tool IoC sharing between Elasticsearch, Chainsaw, and Wireshark
- Progressive disclosure for session resumption
- Persistent storage with FIFO management (8GB limit)
- Smart extraction to minimize storage and context usage
"""

from typing import Any

from fastmcp import FastMCP

from src.storage.investigation_state import InvestigationStateClient
from src.storage.models import (
    IoC,
    IoCSource,
    IoCType,
    Severity,
    SourceType,
)

# Global client instance (singleton for session)
_investigation_client: InvestigationStateClient | None = None


def get_investigation_client() -> InvestigationStateClient:
    """Get or create the investigation state client singleton."""
    global _investigation_client
    if _investigation_client is None:
        _investigation_client = InvestigationStateClient()
    return _investigation_client


class InvestigationStateTools:
    """MCP tools for investigation state management."""

    def __init__(self):
        """Initialize investigation state tools."""
        self.logger = None

    def register_tools(self, mcp: FastMCP):
        """Register all investigation state tools with MCP."""

        @mcp.tool()
        def list_investigations(
            limit: int = 10, status: str | None = None, include_size: bool = False
        ) -> dict[str, Any]:
            """
            List recent investigations with optional filtering.

            This tool shows the most recent investigations to help resume work
            or review past investigations.

            Args:
                limit: Maximum number of investigations to return (default: 10)
                status: Filter by status - "active", "paused", "closed", "archived"
                include_size: Recalculate actual sizes (slower but accurate)

            Returns:
                Dictionary with:
                - investigations: List of investigation summaries
                - total_count: Total number of investigations
                - storage_stats: Current storage usage

            Example:
                list_investigations(limit=5, status="active")
            """
            client = get_investigation_client()

            from src.storage.models import InvestigationStatus

            status_enum = None
            if status:
                try:
                    status_enum = InvestigationStatus(status.lower())
                except ValueError:
                    return {
                        "error": f"Invalid status: {status}",
                        "valid_statuses": [s.value for s in InvestigationStatus],
                    }

            investigations = client.storage.list_investigations(
                limit=limit, status=status_enum, include_size=include_size
            )

            # Format for display
            inv_list = []
            for inv in investigations:
                inv_list.append(
                    {
                        "id": inv.id,
                        "name": inv.name,
                        "status": inv.status.value,
                        "severity": inv.severity.value,
                        "created_at": inv.created_at.isoformat(),
                        "updated_at": inv.updated_at.isoformat(),
                        "ioc_count": inv.ioc_count,
                        "sources": inv.sources,
                        "tags": inv.tags,
                        "size_bytes": inv.size_bytes,
                    }
                )

            return {
                "investigations": inv_list,
                "total_count": len(inv_list),
                "active_investigation": client.active_investigation_id,
                "storage_stats": client.get_storage_stats(),
            }

        @mcp.tool()
        def create_investigation(
            name: str, description: str = "", tags: list[str] | None = None, severity: str = "medium"
        ) -> dict[str, Any]:
            """
            Create a new investigation and make it active.

            This creates a new investigation that will collect IoCs and findings
            from all threat hunting tools (Elasticsearch, Chainsaw, Wireshark).

            Args:
                name: Investigation name (e.g., "Ransomware Incident 2024-01")
                description: Detailed description of the investigation
                tags: List of tags for categorization
                severity: Severity level - "critical", "high", "medium", "low", "info"

            Returns:
                Dictionary with:
                - id: New investigation ID
                - name: Investigation name
                - status: Current status
                - message: Confirmation message

            Example:
                create_investigation(
                    name="Suspected APT Activity",
                    description="Investigating unusual C2 traffic patterns",
                    tags=["apt", "c2", "network"],
                    severity="high"
                )
            """
            client = get_investigation_client()

            # Parse severity
            try:
                sev = Severity(severity.lower())
            except ValueError:
                return {"error": f"Invalid severity: {severity}", "valid_severities": [s.value for s in Severity]}

            investigation = client.create_investigation(
                name=name,
                description=description,
                tags=tags or [],
                severity=sev,
            )

            return {
                "id": investigation.manifest.id,
                "name": investigation.manifest.name,
                "status": investigation.manifest.status.value,
                "severity": investigation.manifest.severity.value,
                "created_at": investigation.manifest.created_at.isoformat(),
                "message": f"Investigation '{name}' created and activated",
                "tip": "Use threat hunting tools to add findings, or add_iocs_to_investigation() for manual IoCs",
            }

        @mcp.tool()
        def resume_investigation(investigation_id: str) -> dict[str, Any]:
            """
            Resume an existing investigation and make it active.

            This loads a previous investigation so new findings will be added to it.
            All IoCs and timeline events are preserved from previous sessions.

            Args:
                investigation_id: ID of the investigation to resume (e.g., "INV-20241228-123456")

            Returns:
                Dictionary with:
                - id: Investigation ID
                - name: Investigation name
                - ioc_count: Number of IoCs collected
                - sources_used: Tools that contributed findings
                - summary: Brief status summary

            Example:
                resume_investigation("INV-20241228-123456")
            """
            client = get_investigation_client()

            investigation = client.resume_investigation(investigation_id)

            if investigation is None:
                return {
                    "error": f"Investigation not found: {investigation_id}",
                    "tip": "Use list_investigations() to see available investigations",
                }

            return {
                "id": investigation.manifest.id,
                "name": investigation.manifest.name,
                "status": investigation.manifest.status.value,
                "severity": investigation.manifest.severity.value,
                "session_count": investigation.manifest.session_count,
                "ioc_count": investigation.iocs.total_count,
                "iocs_by_type": investigation.iocs.by_type,
                "sources_used": investigation.manifest.sources_used,
                "timeline_events": len(investigation.timeline),
                "last_updated": investigation.manifest.updated_at.isoformat(),
                "message": f"Investigation '{investigation.manifest.name}' resumed",
                "tip": "Continue threat hunting or use get_investigation_summary() for details",
            }

        @mcp.tool()
        def get_investigation_summary(format: str = "detailed", investigation_id: str | None = None) -> dict[str, Any]:
            """
            Get a comprehensive summary of an investigation.

            This provides an overview of all collected IoCs, timeline events,
            findings from different tools, and investigation statistics.

            Args:
                format: Output format - "detailed", "compact", or "json"
                investigation_id: Specific investigation ID (uses active if not specified)

            Returns:
                Investigation summary with IoCs, timeline, and statistics

            Example:
                get_investigation_summary(format="compact")
            """
            client = get_investigation_client()

            # Get the investigation
            if investigation_id:
                investigation = client.load_investigation(investigation_id)
            else:
                investigation = client.active_investigation

            if investigation is None:
                return {
                    "error": "No active investigation",
                    "tip": "Use create_investigation() or resume_investigation() first",
                }

            if format == "compact" or format == "detailed":
                return {
                    "summary": client.get_summary(format=format),
                    "investigation_id": investigation.manifest.id,
                }
            # json format
            return {
                "id": investigation.manifest.id,
                "name": investigation.manifest.name,
                "description": investigation.manifest.description,
                "status": investigation.manifest.status.value,
                "severity": investigation.manifest.severity.value,
                "created_at": investigation.manifest.created_at.isoformat(),
                "updated_at": investigation.manifest.updated_at.isoformat(),
                "statistics": {
                    "total_iocs": investigation.iocs.total_count,
                    "iocs_by_type": investigation.iocs.by_type,
                    "iocs_by_source": investigation.iocs.by_source,
                    "timeline_events": len(investigation.timeline),
                    "sources_used": investigation.manifest.sources_used,
                },
                "tags": investigation.manifest.tags,
                "kill_chain_stages": investigation.manifest.kill_chain_stages,
            }

        @mcp.tool()
        def add_iocs_to_investigation(
            iocs: list[dict[str, Any]], investigation_id: str | None = None
        ) -> dict[str, Any]:
            """
            Manually add IoCs to an investigation.

            Use this to add IoCs discovered through manual analysis or
            from external threat intelligence feeds.

            Args:
                iocs: List of IoC dictionaries with:
                    - type: IoC type ("ip", "domain", "hash", "user", "hostname", "process", etc.)
                    - value: The IoC value
                    - tags: Optional list of tags
                    - context: Optional context dictionary
                investigation_id: Target investigation (uses active if not specified)

            Returns:
                Dictionary with count of IoCs added

            Example:
                add_iocs_to_investigation([
                    {"type": "ip", "value": "203.0.113.42", "tags": ["c2", "malicious"]},
                    {"type": "domain", "value": "evil-c2.com", "tags": ["c2"]},
                    {"type": "hash", "value": "abc123def456...", "tags": ["malware"]}
                ])
            """
            client = get_investigation_client()

            # Check for active investigation
            if investigation_id:
                client.resume_investigation(investigation_id)

            if client.active_investigation is None:
                return {
                    "error": "No active investigation",
                    "tip": "Use create_investigation() or resume_investigation() first",
                }

            # Convert to IoC objects
            ioc_objects = []
            for ioc_data in iocs:
                try:
                    ioc_type = IoCType(ioc_data.get("type", "other").lower())
                except ValueError:
                    ioc_type = IoCType.OTHER

                ioc = IoC(
                    type=ioc_type,
                    value=ioc_data["value"],
                    tags=ioc_data.get("tags", []),
                    context=ioc_data.get("context", {}),
                    sources=[
                        IoCSource(
                            tool="manual_add",
                            source_type=SourceType.MANUAL,
                            investigation_id=client.active_investigation_id,
                        )
                    ],
                )
                ioc_objects.append(ioc)

            added = client.add_iocs(ioc_objects)

            return {
                "iocs_added": added,
                "iocs_provided": len(iocs),
                "iocs_merged": len(iocs) - added,
                "investigation_id": client.active_investigation_id,
                "total_iocs": client.active_investigation.iocs.total_count,
                "message": f"Added {added} new IoCs, merged {len(iocs) - added} duplicates",
            }

        @mcp.tool()
        def get_shared_iocs(
            ioc_types: list[str] | None = None,
            min_priority: int = 1,
            sources: list[str] | None = None,
            active_only: bool = False,
            limit: int = 100,
        ) -> dict[str, Any]:
            """
            Get IoCs shared across investigations and tools.

            This retrieves IoCs collected from all sources (Elasticsearch, Chainsaw,
            Wireshark) that can be used for cross-tool correlation and hunting.

            Args:
                ioc_types: Filter by IoC types (e.g., ["ip", "domain", "hash"])
                min_priority: Minimum Pyramid of Pain priority (1-6, higher = more valuable)
                sources: Filter by source tools (e.g., ["elasticsearch", "chainsaw"])
                active_only: Only from active investigation
                limit: Maximum IoCs to return (default: 100)

            Returns:
                Dictionary with:
                - iocs: List of IoCs with source information
                - total_count: Total matching IoCs
                - by_type: Counts by IoC type
                - by_source: Counts by source tool

            Pyramid of Pain Priority:
                1 = Hash (trivial to change)
                2 = IP (easy to change)
                3 = Domain (simple to change)
                4 = User/Hostname (annoying to change)
                5 = Process/Tool (challenging to change)
                6 = TTP/CommandLine (tough to change)

            Example:
                get_shared_iocs(
                    ioc_types=["ip", "domain"],
                    min_priority=2,
                    sources=["elasticsearch", "chainsaw"]
                )
            """
            client = get_investigation_client()

            # Parse IoC types
            ioc_type_enums = None
            if ioc_types:
                ioc_type_enums = []
                for t in ioc_types:
                    try:
                        ioc_type_enums.append(IoCType(t.lower()))
                    except ValueError:
                        pass  # Skip invalid types

            # Parse source types
            source_type_enums = None
            if sources:
                source_type_enums = []
                for s in sources:
                    try:
                        source_type_enums.append(SourceType(s.lower()))
                    except ValueError:
                        pass

            shared_iocs = client.get_shared_iocs(
                ioc_types=ioc_type_enums,
                min_priority=min_priority,
                sources=source_type_enums,
                active_only=active_only,
                limit=limit,
            )

            # Format for output
            ioc_list = []
            by_type = {}
            by_source = {}

            for ioc in shared_iocs:
                ioc_dict = {
                    "type": ioc.type.value,
                    "value": ioc.value,
                    "priority": ioc.pyramid_priority,
                    "occurrences": ioc.total_occurrences,
                    "sources": [s.tool for s in ioc.sources],
                    "tags": ioc.tags,
                    "first_seen": ioc.first_seen.isoformat(),
                    "last_seen": ioc.last_seen.isoformat(),
                }
                ioc_list.append(ioc_dict)

                # Count by type
                type_key = ioc.type.value
                by_type[type_key] = by_type.get(type_key, 0) + 1

                # Count by source
                for source in ioc.sources:
                    by_source[source.tool] = by_source.get(source.tool, 0) + 1

            return {
                "iocs": ioc_list,
                "total_count": len(ioc_list),
                "by_type": by_type,
                "by_source": by_source,
                "filters_applied": {
                    "ioc_types": ioc_types,
                    "min_priority": min_priority,
                    "sources": sources,
                    "active_only": active_only,
                },
                "tip": "Use these IoCs with hunt_for_ioc() or other threat hunting tools",
            }

        @mcp.tool()
        def export_iocs(
            format: str = "json",
            ioc_types: list[str] | None = None,
            min_priority: int = 1,
            investigation_id: str | None = None,
        ) -> dict[str, Any]:
            """
            Export IoCs from an investigation in various formats.

            Exports collected IoCs for use in other security tools,
            threat intelligence platforms, or reporting.

            Args:
                format: Export format - "json", "csv", "values", or "stix"
                ioc_types: Filter by IoC types (e.g., ["ip", "domain"])
                min_priority: Minimum priority to include (1-6)
                investigation_id: Specific investigation (uses active if not specified)

            Returns:
                Exported IoCs in the specified format

            Formats:
                - json: Full IoC details as JSON
                - csv: Comma-separated values
                - values: Plain list of values (one per line)
                - stix: STIX 2.1 format (for threat intel platforms)

            Example:
                export_iocs(format="values", ioc_types=["ip"])
            """
            client = get_investigation_client()

            # Parse IoC types
            ioc_type_enums = None
            if ioc_types:
                ioc_type_enums = []
                for t in ioc_types:
                    try:
                        ioc_type_enums.append(IoCType(t.lower()))
                    except ValueError:
                        pass

            result = client.export_iocs(
                format=format,
                ioc_types=ioc_type_enums,
                min_priority=min_priority,
            )

            return result

        @mcp.tool()
        def close_investigation(resolution: str = "", investigation_id: str | None = None) -> dict[str, Any]:
            """
            Close an investigation with a resolution summary.

            This marks the investigation as closed and records the resolution.
            Closed investigations are retained for reference and can be reopened.

            Args:
                resolution: Summary of investigation findings/outcome
                investigation_id: Specific investigation (uses active if not specified)

            Returns:
                Confirmation with final statistics

            Example:
                close_investigation(
                    resolution="Confirmed ransomware. Contained to 3 hosts. Remediation complete."
                )
            """
            client = get_investigation_client()

            if investigation_id:
                client.resume_investigation(investigation_id)

            if client.active_investigation is None:
                return {"error": "No active investigation to close", "tip": "Use resume_investigation() first"}

            inv_id = client.active_investigation_id
            inv_name = client.active_investigation.manifest.name
            stats = {
                "total_iocs": client.active_investigation.iocs.total_count,
                "timeline_events": len(client.active_investigation.timeline),
                "sources_used": client.active_investigation.manifest.sources_used,
            }

            client.close_investigation(resolution=resolution)

            return {
                "id": inv_id,
                "name": inv_name,
                "status": "closed",
                "resolution": resolution,
                "final_statistics": stats,
                "message": f"Investigation '{inv_name}' closed",
                "tip": "Use resume_investigation() to reopen if needed",
            }

        @mcp.tool()
        def cleanup_storage(force: bool = False, keep_count: int = 10) -> dict[str, Any]:
            """
            Cleanup investigation storage and enforce size limits.

            This compacts old investigations and removes the oldest if
            storage exceeds the 8GB limit (FIFO policy).

            Args:
                force: Force cleanup even if under limit
                keep_count: Minimum investigations to keep (default: 10)

            Returns:
                Cleanup results with bytes freed

            Example:
                cleanup_storage(force=True)
            """
            client = get_investigation_client()

            # Get initial stats
            initial_stats = client.get_storage_stats()

            # Perform cleanup
            results = client.storage.cleanup(
                keep_count=keep_count,
                force=force,
            )

            return {
                "initial_size_bytes": results["initial_size"],
                "final_size_bytes": results["final_size"],
                "bytes_freed": results["bytes_freed"],
                "investigations_deleted": results["deleted"],
                "investigations_compacted": list(results["compacted"].keys()),
                "storage_stats": client.get_storage_stats(),
                "message": f"Freed {results['bytes_freed']} bytes",
            }

        @mcp.tool()
        def get_progressive_disclosure() -> dict[str, Any]:
            """
            Get progressive disclosure prompt for session start.

            This provides a summary of recent investigations and shared IoCs
            to help resume work efficiently at the start of a new session.

            Returns:
                Dictionary with:
                - prompt: Human-readable summary for context
                - recent_investigations: List of recent investigations
                - shared_iocs_count: Number of shared IoCs available
                - storage_stats: Current storage usage

            Use at session start to understand available context.

            Example:
                get_progressive_disclosure()
            """
            client = get_investigation_client()

            prompt = client.get_progressive_disclosure_prompt()
            recent = client.storage.list_investigations(limit=10)
            shared = client.get_shared_iocs(limit=100)

            return {
                "prompt": prompt,
                "recent_investigations": [
                    {
                        "id": inv.id,
                        "name": inv.name,
                        "status": inv.status.value,
                        "ioc_count": inv.ioc_count,
                        "updated_at": inv.updated_at.isoformat(),
                    }
                    for inv in recent
                ],
                "shared_iocs_available": len(shared),
                "storage_stats": client.get_storage_stats(),
                "tip": "Use resume_investigation() to continue a previous investigation",
            }
