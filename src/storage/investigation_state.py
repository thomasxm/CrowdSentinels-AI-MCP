"""Investigation state client for managing persistent investigation state."""

import json
import logging
from datetime import datetime
from typing import Any

from src.storage.config import StorageConfig, get_config
from src.storage.models import (
    IndexEntry,
    Investigation,
    InvestigationManifest,
    InvestigationStatus,
    IoC,
    IoCCollection,
    IoCSource,
    IoCType,
    Severity,
    SourceFindings,
    SourceType,
    TimelineEvent,
)
from src.storage.smart_extractor import SmartExtractor
from src.storage.storage_manager import StorageManager

logger = logging.getLogger(__name__)


class InvestigationStateClient:
    """Client for managing investigation state across sessions and tools."""

    def __init__(self, config: StorageConfig | None = None):
        """Initialize the investigation state client."""
        self.config = config or get_config()
        self.storage = StorageManager(self.config)
        self.extractor = SmartExtractor(
            max_iocs=self.config.storage.max_iocs_per_investigation,
            max_events=self.config.extraction.max_events_to_keep,
        )
        self._active_investigation: Investigation | None = None
        self._active_id: str | None = None

    @property
    def active_investigation(self) -> Investigation | None:
        """Get the currently active investigation."""
        return self._active_investigation

    @property
    def active_investigation_id(self) -> str | None:
        """Get the ID of the currently active investigation."""
        return self._active_id

    def create_investigation(
        self,
        name: str,
        description: str = "",
        tags: list[str] | None = None,
        severity: Severity = Severity.UNKNOWN,
        auto_activate: bool = True,
    ) -> Investigation:
        """
        Create a new investigation.

        Args:
            name: Investigation name
            description: Description of the investigation
            tags: Tags for categorization
            severity: Initial severity level
            auto_activate: Automatically set as active investigation

        Returns:
            The created Investigation
        """
        # Enforce storage limits first
        self.storage.enforce_limit()

        # Create investigation
        investigation = Investigation.create(
            name=name,
            description=description,
            tags=tags,
        )
        investigation.manifest.severity = severity

        # Create directory structure
        inv_path = self.storage.create_investigation_dir(investigation.manifest.id)

        # Save initial state
        self._save_investigation(investigation)

        # Update index
        self.storage.index.add_investigation(investigation.manifest)
        self.storage._save_index()

        logger.info(f"Created investigation: {investigation.manifest.id} - {name}")

        if auto_activate:
            self._active_investigation = investigation
            self._active_id = investigation.manifest.id

        return investigation

    def load_investigation(self, investigation_id: str) -> Investigation | None:
        """
        Load an investigation from storage.

        Args:
            investigation_id: ID of the investigation to load

        Returns:
            The loaded Investigation or None if not found
        """
        inv_path = self.storage.get_investigation_path(investigation_id)
        if not inv_path.exists():
            logger.warning(f"Investigation not found: {investigation_id}")
            return None

        try:
            # Load manifest
            manifest_path = inv_path / "manifest.json"
            manifest = InvestigationManifest.model_validate(json.loads(manifest_path.read_text()))

            # Load IoCs
            iocs_path = inv_path / "iocs" / "extracted.json"
            if iocs_path.exists():
                iocs = IoCCollection.model_validate(json.loads(iocs_path.read_text()))
            else:
                iocs = IoCCollection(investigation_id=investigation_id)

            # Load timeline
            timeline_path = inv_path / "timeline" / "events.json"
            timeline = []
            if timeline_path.exists():
                timeline_data = json.loads(timeline_path.read_text())
                events_data = timeline_data.get("events", [])
                for evt in events_data:
                    try:
                        timeline.append(TimelineEvent.model_validate(evt))
                    except Exception:
                        pass  # Skip invalid events

            # Load source findings
            sources_path = inv_path / "sources"
            source_findings = {}
            if sources_path.exists():
                for source_file in sources_path.glob("*.json"):
                    try:
                        findings = SourceFindings.model_validate(json.loads(source_file.read_text()))
                        key = f"{findings.source.value}_{findings.tool}"
                        source_findings[key] = findings
                    except Exception as e:
                        logger.warning(f"Failed to load {source_file}: {e}")

            investigation = Investigation(
                manifest=manifest,
                iocs=iocs,
                timeline=timeline,
                source_findings=source_findings,
            )

            logger.info(f"Loaded investigation: {investigation_id}")
            return investigation

        except Exception as e:
            logger.error(f"Failed to load investigation {investigation_id}: {e}")
            return None

    def resume_investigation(self, investigation_id: str) -> Investigation | None:
        """
        Resume a previous investigation.

        Loads the investigation and sets it as active.

        Args:
            investigation_id: ID of the investigation to resume

        Returns:
            The loaded Investigation or None if not found
        """
        investigation = self.load_investigation(investigation_id)
        if investigation:
            # Update session info
            investigation.manifest.session_count += 1
            investigation.manifest.last_session_at = datetime.utcnow()
            investigation.manifest.update_timestamp()

            # Save updated manifest
            self._save_investigation(investigation)

            # Set as active
            self._active_investigation = investigation
            self._active_id = investigation_id

            logger.info(f"Resumed investigation: {investigation_id}")

        return investigation

    def save_state(self) -> bool:
        """
        Save the current active investigation state.

        Returns:
            True if saved successfully
        """
        if not self._active_investigation:
            logger.warning("No active investigation to save")
            return False

        return self._save_investigation(self._active_investigation)

    def _save_investigation(self, investigation: Investigation) -> bool:
        """Save an investigation to storage."""
        inv_path = self.storage.get_investigation_path(investigation.manifest.id)

        try:
            # Ensure directory exists
            self.storage.create_investigation_dir(investigation.manifest.id)

            # Save manifest
            manifest_path = inv_path / "manifest.json"
            manifest_path.write_text(investigation.manifest.model_dump_json(indent=2))

            # Save IoCs
            iocs_path = inv_path / "iocs" / "extracted.json"
            iocs_path.write_text(investigation.iocs.model_dump_json(indent=2))

            # Save prioritized IoCs (top 20)
            prioritized_path = inv_path / "iocs" / "prioritized.json"
            prioritized = investigation.iocs.get_by_priority(min_priority=4)[:20]
            prioritized_path.write_text(json.dumps([ioc.model_dump() for ioc in prioritized], indent=2, default=str))

            # Save timeline
            timeline_path = inv_path / "timeline" / "events.json"
            timeline_path.write_text(
                json.dumps(
                    {
                        "total_events": len(investigation.timeline),
                        "events": [evt.model_dump() for evt in investigation.timeline],
                    },
                    indent=2,
                    default=str,
                )
            )

            # Save source findings
            for key, findings in investigation.source_findings.items():
                source_path = inv_path / "sources" / f"{key}.json"
                source_path.write_text(findings.model_dump_json(indent=2))

            # Generate and save summary
            self._save_summary(investigation)

            # Update index
            investigation.manifest.size_bytes = self.storage.get_investigation_size(investigation.manifest.id)
            self.storage.index.add_investigation(investigation.manifest)
            self.storage._save_index()

            logger.debug(f"Saved investigation: {investigation.manifest.id}")
            return True

        except Exception as e:
            logger.error(f"Failed to save investigation: {e}")
            return False

    def _save_summary(self, investigation: Investigation) -> None:
        """Generate and save the markdown summary."""
        inv_path = self.storage.get_investigation_path(investigation.manifest.id)
        summary_path = inv_path / "summary.md"

        manifest = investigation.manifest
        iocs = investigation.iocs

        # Build summary markdown
        lines = [
            f"# Investigation: {manifest.id}",
            "",
            f"## {manifest.name}",
            "",
            f"**Status:** {manifest.status.value.title()} | **Severity:** {manifest.severity.value.upper()}",
            f"**Created:** {manifest.created_at.strftime('%Y-%m-%d %H:%M:%S')} UTC",
            f"**Last Updated:** {manifest.updated_at.strftime('%Y-%m-%d %H:%M:%S')} UTC",
            f"**Sessions:** {manifest.session_count}",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
            manifest.description or "No description provided.",
            "",
            "## Statistics",
            "",
            f"- **Total IoCs:** {iocs.total_count}",
            f"- **Events Analyzed:** {manifest.statistics.total_events}",
            f"- **Affected Hosts:** {manifest.statistics.affected_hosts}",
            f"- **Affected Users:** {manifest.statistics.affected_users}",
            f"- **MITRE Techniques:** {manifest.statistics.mitre_techniques}",
            f"- **Sources Used:** {', '.join(manifest.sources_used) or 'None'}",
            "",
        ]

        # Add kill chain stages if present
        if manifest.kill_chain_stages:
            lines.extend(
                [
                    "## Kill Chain Progress",
                    "",
                    f"**Stages Identified:** {' → '.join(manifest.kill_chain_stages)}",
                    "",
                ]
            )

        # Add top IoCs
        priority_iocs = iocs.get_by_priority(min_priority=4)[:10]
        if priority_iocs:
            lines.extend(
                [
                    "## Priority IoCs (Top 10)",
                    "",
                    "| Type | Value | Priority | Occurrences | Sources |",
                    "|------|-------|----------|-------------|---------|",
                ]
            )
            for ioc in priority_iocs:
                value = ioc.value[:50] + "..." if len(ioc.value) > 50 else ioc.value
                sources = ", ".join(s.tool for s in ioc.sources)
                lines.append(
                    f"| {ioc.type.value} | `{value}` | {ioc.pyramid_priority} | {ioc.total_occurrences} | {sources} |"
                )
            lines.append("")

        # Add IoC breakdown by type
        if iocs.by_type:
            lines.extend(
                [
                    "## IoC Breakdown by Type",
                    "",
                ]
            )
            for ioc_type, count in sorted(iocs.by_type.items(), key=lambda x: x[1], reverse=True):
                lines.append(f"- **{ioc_type}:** {count}")
            lines.append("")

        # Add source findings summary
        if investigation.source_findings:
            lines.extend(
                [
                    "## Source Findings",
                    "",
                ]
            )
            for key, findings in investigation.source_findings.items():
                lines.append(f"### {findings.source.value.title()} - {findings.tool}")
                lines.append(f"- Events: {findings.total_events}")
                lines.append(f"- IoCs Extracted: {findings.iocs_extracted}")
                if findings.key_findings:
                    lines.append("- Key Findings:")
                    for finding in findings.key_findings[:5]:
                        lines.append(f"  - {finding}")
                lines.append("")

        # Add tags
        if manifest.tags:
            lines.extend(
                [
                    "## Tags",
                    "",
                    ", ".join(f"`{tag}`" for tag in manifest.tags),
                    "",
                ]
            )

        # Add analyst notes
        if manifest.analyst_notes:
            lines.extend(
                [
                    "## Analyst Notes",
                    "",
                ]
            )
            for note in manifest.analyst_notes:
                lines.append(f"- {note}")
            lines.append("")

        summary_path.write_text("\n".join(lines))

    def add_iocs(
        self,
        iocs: list[IoC],
        source: str = "manual",
        source_type: SourceType = SourceType.OTHER,
        investigation_id: str | None = None,
    ) -> int:
        """
        Add IoCs to an investigation.

        Args:
            iocs: List of IoCs to add
            source: Source tool name
            source_type: Type of source
            investigation_id: Target investigation (uses active if not specified)

        Returns:
            Number of new IoCs added (not merged)
        """
        investigation = self._get_investigation(investigation_id)
        if not investigation:
            return 0

        new_count = 0
        for ioc in iocs:
            # Ensure source is set
            if not ioc.sources:
                ioc.sources.append(
                    IoCSource(
                        tool=source,
                        source_type=source_type,
                        investigation_id=investigation.manifest.id,
                    )
                )

            if investigation.iocs.add_ioc(ioc):
                new_count += 1

        # Update statistics
        investigation.manifest.statistics.total_iocs = investigation.iocs.total_count
        investigation.manifest.update_timestamp()

        # Save if active
        if investigation_id is None or investigation_id == self._active_id:
            self.save_state()

        logger.info(f"Added {new_count} new IoCs (total: {investigation.iocs.total_count})")
        return new_count

    def add_iocs_from_results(
        self,
        results: dict[str, Any],
        source_type: SourceType,
        source_tool: str,
        investigation_id: str | None = None,
    ) -> int:
        """
        Extract and add IoCs from search results.

        Args:
            results: Search results (ES, Chainsaw, etc.)
            source_type: Type of source
            source_tool: Tool name
            investigation_id: Target investigation

        Returns:
            Number of new IoCs added
        """
        investigation = self._get_investigation(investigation_id)
        if not investigation:
            return 0

        # Extract IoCs based on source type
        if source_type == SourceType.ELASTICSEARCH:
            iocs = self.extractor.extract_iocs_from_elasticsearch(results, source_tool, investigation.manifest.id)
        elif source_type == SourceType.CHAINSAW:
            iocs = self.extractor.extract_iocs_from_chainsaw(results, source_tool, investigation.manifest.id)
        elif source_type == SourceType.WIRESHARK:
            iocs = self.extractor.extract_iocs_from_wireshark(results, source_tool, investigation.manifest.id)
        else:
            # Generic extraction from hits
            iocs = self.extractor.extract_iocs_from_elasticsearch(results, source_tool, investigation.manifest.id)

        return self.add_iocs(iocs, source_tool, source_type, investigation_id)

    def add_findings(
        self,
        source_type: SourceType,
        source_tool: str,
        results: dict[str, Any],
        query_description: str | None = None,
        investigation_id: str | None = None,
        extract_iocs: bool = True,
        extract_timeline: bool = True,
    ) -> dict[str, Any]:
        """
        Add findings from a tool to the investigation.

        This is the main method for tools to save their results.

        Args:
            source_type: Type of source (elasticsearch, chainsaw, etc.)
            source_tool: Name of the tool
            results: Raw results from the tool
            query_description: Description of the query
            investigation_id: Target investigation
            extract_iocs: Whether to extract IoCs
            extract_timeline: Whether to extract timeline events

        Returns:
            Summary of what was added
        """
        investigation = self._get_investigation(investigation_id)
        if not investigation:
            return {"error": "No investigation found"}

        summary = {
            "iocs_added": 0,
            "timeline_events_added": 0,
            "source": source_type.value,
            "tool": source_tool,
        }

        # Get events from results
        if source_type == SourceType.ELASTICSEARCH:
            events = results.get("hits", {}).get("hits", [])
            events = [e.get("_source", {}) for e in events]
        elif source_type == SourceType.CHAINSAW:
            events = results.get("detections", [])
        else:
            events = results.get("events", []) or results.get("hits", {}).get("hits", [])

        # Create source findings summary
        findings = self.extractor.summarize_events(events, source_type, source_tool)
        findings.query_description = query_description

        # Extract and add IoCs
        if extract_iocs:
            iocs_added = self.add_iocs_from_results(results, source_type, source_tool, investigation.manifest.id)
            findings.iocs_extracted = iocs_added
            summary["iocs_added"] = iocs_added

        # Extract and add timeline events
        if extract_timeline and events:
            timeline_events = self.extractor.extract_timeline_events(events, source_type, source_tool)
            for event in timeline_events:
                investigation.add_timeline_event(event)
            summary["timeline_events_added"] = len(timeline_events)

        # Add findings to investigation
        investigation.add_source_findings(findings)

        # Update statistics
        stats = investigation.manifest.statistics
        stats.total_events += findings.total_events
        stats.mitre_techniques = len(set(t for f in investigation.source_findings.values() for t in f.mitre_techniques))

        # Count unique hosts and users
        hosts = set()
        users = set()
        for ioc in investigation.iocs.iocs:
            if ioc.type == IoCType.HOSTNAME:
                hosts.add(ioc.value)
            elif ioc.type == IoCType.USER:
                users.add(ioc.value)
        stats.affected_hosts = len(hosts)
        stats.affected_users = len(users)

        investigation.manifest.update_timestamp()
        self.save_state()

        return summary

    def get_summary(
        self,
        investigation_id: str | None = None,
        format: str = "markdown",
    ) -> str:
        """
        Get investigation summary.

        Args:
            investigation_id: Investigation ID (uses active if not specified)
            format: Output format (markdown, json, compact)

        Returns:
            Summary string
        """
        investigation = self._get_investigation(investigation_id)
        if not investigation:
            return "No investigation found"

        if format == "json":
            return investigation.manifest.model_dump_json(indent=2)

        if format == "compact":
            m = investigation.manifest
            return (
                f"[{m.severity.value.upper()}] {m.id} - {m.name}\n"
                f"IoCs: {m.statistics.total_iocs} | "
                f"Hosts: {m.statistics.affected_hosts} | "
                f"Users: {m.statistics.affected_users}\n"
                f"Sources: {', '.join(m.sources_used)}\n"
                f"Updated: {m.updated_at.strftime('%Y-%m-%d %H:%M')}"
            )

        # Default: read markdown summary
        inv_path = self.storage.get_investigation_path(investigation.manifest.id)
        summary_path = inv_path / "summary.md"
        if summary_path.exists():
            return summary_path.read_text()

        # Generate if not exists
        self._save_summary(investigation)
        return summary_path.read_text()

    def get_shared_iocs(
        self,
        ioc_types: list[IoCType] | None = None,
        min_priority: int = 1,
        sources: list[str] | None = None,
        active_only: bool = True,
        limit: int = 100,
    ) -> list[IoC]:
        """
        Get IoCs shared across investigations.

        Args:
            ioc_types: Filter by IoC types
            min_priority: Minimum pyramid priority
            sources: Filter by source tools
            active_only: Only include active investigations
            limit: Maximum IoCs to return

        Returns:
            List of IoCs from all matching investigations
        """
        all_iocs: dict[str, IoC] = {}

        # Get investigations
        investigations = self.storage.list_investigations(
            limit=100,
            status=InvestigationStatus.ACTIVE if active_only else None,
        )

        for entry in investigations:
            investigation = self.load_investigation(entry.id)
            if not investigation:
                continue

            for ioc in investigation.iocs.iocs:
                # Apply filters
                if ioc_types and ioc.type not in ioc_types:
                    continue
                if ioc.pyramid_priority < min_priority:
                    continue
                if sources and not any(s.tool in sources for s in ioc.sources):
                    continue

                # Merge or add
                key = f"{ioc.type.value}:{ioc.value}"
                if key in all_iocs:
                    all_iocs[key].merge_with(ioc)
                else:
                    all_iocs[key] = ioc.model_copy(deep=True)

        # Sort by priority and occurrence
        sorted_iocs = sorted(all_iocs.values(), key=lambda x: (x.pyramid_priority, x.total_occurrences), reverse=True)

        return sorted_iocs[:limit]

    def export_iocs(
        self,
        investigation_id: str | None = None,
        format: str = "json",
        ioc_types: list[IoCType] | None = None,
        min_priority: int = 1,
    ) -> str | dict:
        """
        Export IoCs from an investigation.

        Args:
            investigation_id: Investigation to export from
            format: Export format (json, csv, stix, misp)
            ioc_types: Filter by types
            min_priority: Minimum priority

        Returns:
            Exported IoCs in requested format
        """
        investigation = self._get_investigation(investigation_id)
        if not investigation:
            return {"error": "No investigation found"}

        iocs = investigation.iocs.get_by_priority(min_priority)
        if ioc_types:
            iocs = [i for i in iocs if i.type in ioc_types]

        if format == "json":
            return {
                "investigation_id": investigation.manifest.id,
                "exported_at": datetime.utcnow().isoformat(),
                "total_iocs": len(iocs),
                "iocs": [ioc.model_dump() for ioc in iocs],
            }

        if format == "csv":
            lines = ["type,value,priority,occurrences,sources,first_seen,last_seen"]
            for ioc in iocs:
                sources = "|".join(s.tool for s in ioc.sources)
                lines.append(
                    f"{ioc.type.value},{ioc.value},{ioc.pyramid_priority},"
                    f"{ioc.total_occurrences},{sources},"
                    f"{ioc.first_seen.isoformat()},{ioc.last_seen.isoformat()}"
                )
            return "\n".join(lines)

        if format == "values":
            # Simple list of values for use in other tools
            return "\n".join(ioc.value for ioc in iocs)

        return {"error": f"Unknown format: {format}"}

    def close_investigation(
        self,
        investigation_id: str | None = None,
        resolution: str = "",
    ) -> bool:
        """
        Close an investigation.

        Args:
            investigation_id: Investigation to close
            resolution: Resolution notes

        Returns:
            True if closed successfully
        """
        investigation = self._get_investigation(investigation_id)
        if not investigation:
            return False

        investigation.manifest.status = InvestigationStatus.CLOSED
        investigation.manifest.resolution = resolution
        investigation.manifest.update_timestamp()

        self._save_investigation(investigation)

        # Clear active if this was active
        if investigation.manifest.id == self._active_id:
            self._active_investigation = None
            self._active_id = None

        logger.info(f"Closed investigation: {investigation.manifest.id}")
        return True

    def list_investigations(
        self,
        limit: int = 10,
        status: InvestigationStatus | None = None,
        severity: Severity | None = None,
    ) -> list[IndexEntry]:
        """
        List investigations.

        Args:
            limit: Maximum to return
            status: Filter by status
            severity: Filter by severity

        Returns:
            List of investigation index entries
        """
        entries = self.storage.list_investigations(limit=limit * 2, status=status)

        if severity:
            entries = [e for e in entries if e.severity == severity]

        return entries[:limit]

    def get_progressive_disclosure_prompt(self) -> str:
        """
        Generate the progressive disclosure prompt for session start.

        Returns:
            Formatted prompt showing recent investigations
        """
        if not self.config.progressive_disclosure.enabled:
            return ""

        max_shown = self.config.progressive_disclosure.max_investigations_shown
        recent = self.list_investigations(limit=max_shown, status=InvestigationStatus.ACTIVE)

        if not recent:
            return ""

        lines = [
            "Welcome back! You have active investigations:",
            "",
        ]

        for i, entry in enumerate(recent, 1):
            age = datetime.utcnow() - entry.updated_at
            if age.days > 0:
                age_str = f"{age.days} day(s) ago"
            elif age.seconds > 3600:
                age_str = f"{age.seconds // 3600} hour(s) ago"
            else:
                age_str = f"{age.seconds // 60} minute(s) ago"

            lines.append(f"{i}. [{entry.severity.value.upper()}] {entry.id} - {entry.name}")
            lines.append(
                f"   Last updated: {age_str} | {entry.ioc_count} IoCs | Sources: {', '.join(entry.sources) or 'None'}"
            )
            lines.append("")

        lines.append("Would you like to resume an investigation or start a new one?")

        return "\n".join(lines)

    def _get_investigation(self, investigation_id: str | None = None) -> Investigation | None:
        """Get investigation by ID or return active."""
        if investigation_id:
            if investigation_id == self._active_id:
                return self._active_investigation
            return self.load_investigation(investigation_id)
        return self._active_investigation

    def add_analyst_note(
        self,
        note: str,
        investigation_id: str | None = None,
    ) -> bool:
        """Add an analyst note to the investigation."""
        investigation = self._get_investigation(investigation_id)
        if not investigation:
            return False

        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
        investigation.manifest.analyst_notes.append(f"[{timestamp}] {note}")
        investigation.manifest.update_timestamp()
        self.save_state()
        return True

    def set_severity(
        self,
        severity: Severity,
        investigation_id: str | None = None,
    ) -> bool:
        """Set the severity of an investigation."""
        investigation = self._get_investigation(investigation_id)
        if not investigation:
            return False

        investigation.manifest.severity = severity
        investigation.manifest.update_timestamp()
        self.save_state()
        return True

    def add_kill_chain_stage(
        self,
        stage: str,
        investigation_id: str | None = None,
    ) -> bool:
        """Add a kill chain stage to the investigation."""
        investigation = self._get_investigation(investigation_id)
        if not investigation:
            return False

        if stage not in investigation.manifest.kill_chain_stages:
            investigation.manifest.kill_chain_stages.append(stage)
            investigation.manifest.update_timestamp()
            self.save_state()
        return True

    def get_storage_stats(self) -> dict[str, Any]:
        """Get storage statistics."""
        return self.storage.get_storage_stats()

    def cleanup_storage(self, keep_count: int = 10, force: bool = False) -> dict[str, Any]:
        """Manual storage cleanup."""
        return self.storage.cleanup(keep_count=keep_count, force=force)
