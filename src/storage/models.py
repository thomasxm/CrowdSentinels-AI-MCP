"""Pydantic models for investigation state storage."""

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class InvestigationStatus(str, Enum):
    """Investigation status enum."""
    ACTIVE = "active"
    PAUSED = "paused"
    CLOSED = "closed"
    ARCHIVED = "archived"


class Severity(str, Enum):
    """Severity level enum."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class IoCType(str, Enum):
    """IoC type enum."""
    IP = "ip"
    DOMAIN = "domain"
    HASH = "hash"
    URL = "url"
    USER = "user"
    HOSTNAME = "hostname"
    PROCESS = "process"
    COMMANDLINE = "commandline"
    FILE_PATH = "file_path"
    REGISTRY_KEY = "registry_key"
    SERVICE = "service"
    SCHEDULED_TASK = "scheduled_task"
    EMAIL = "email"
    OTHER = "other"


class SourceType(str, Enum):
    """Data source type enum."""
    ELASTICSEARCH = "elasticsearch"
    CHAINSAW = "chainsaw"
    WIRESHARK = "wireshark"
    MANUAL = "manual"
    OTHER = "other"


class IoCSource(BaseModel):
    """Source information for an IoC."""
    tool: str
    source_type: SourceType = SourceType.OTHER
    investigation_id: str | None = None
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    query_context: str | None = None
    occurrence_count: int = 1


class IoC(BaseModel):
    """Individual Indicator of Compromise."""
    id: str = Field(default_factory=lambda: f"ioc-{uuid.uuid4().hex[:8]}")
    type: IoCType
    value: str
    pyramid_priority: int = Field(ge=1, le=6, default=3)
    sources: list[IoCSource] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    total_occurrences: int = 1
    context: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)
    related_iocs: list[str] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0.0, le=1.0, default=0.5)
    is_malicious: bool | None = None

    def merge_with(self, other: "IoC") -> "IoC":
        """Merge another IoC into this one (for deduplication)."""
        if self.value != other.value or self.type != other.type:
            raise ValueError("Cannot merge IoCs with different type/value")

        # Merge sources
        existing_tools = {s.tool for s in self.sources}
        for source in other.sources:
            if source.tool not in existing_tools:
                self.sources.append(source)
            else:
                # Update existing source
                for existing in self.sources:
                    if existing.tool == source.tool:
                        existing.last_seen = max(existing.last_seen, source.last_seen)
                        existing.occurrence_count += source.occurrence_count

        # Update timestamps
        self.first_seen = min(self.first_seen, other.first_seen)
        self.last_seen = max(self.last_seen, other.last_seen)
        self.total_occurrences += other.total_occurrences

        # Merge tags and related IoCs
        self.tags = list(set(self.tags + other.tags))
        self.related_iocs = list(set(self.related_iocs + other.related_iocs))
        self.mitre_techniques = list(set(self.mitre_techniques + other.mitre_techniques))

        # Update priority (keep highest)
        self.pyramid_priority = max(self.pyramid_priority, other.pyramid_priority)

        # Update confidence (average)
        self.confidence = (self.confidence + other.confidence) / 2

        # Merge context
        self.context.update(other.context)

        return self


class IoCCollection(BaseModel):
    """Collection of IoCs for an investigation."""
    investigation_id: str
    extracted_at: datetime = Field(default_factory=datetime.utcnow)
    total_count: int = 0
    by_type: dict[str, int] = Field(default_factory=dict)
    by_source: dict[str, int] = Field(default_factory=dict)
    iocs: list[IoC] = Field(default_factory=list)

    def add_ioc(self, ioc: IoC) -> bool:
        """Add or merge an IoC. Returns True if new, False if merged."""
        # Check for existing IoC with same type and value
        for existing in self.iocs:
            if existing.type == ioc.type and existing.value == ioc.value:
                existing.merge_with(ioc)
                self._update_counts()
                return False

        # New IoC
        self.iocs.append(ioc)
        self._update_counts()
        return True

    def _update_counts(self) -> None:
        """Update count statistics."""
        self.total_count = len(self.iocs)
        self.by_type = {}
        self.by_source = {}

        for ioc in self.iocs:
            # Count by type
            type_key = ioc.type.value if isinstance(ioc.type, IoCType) else str(ioc.type)
            self.by_type[type_key] = self.by_type.get(type_key, 0) + 1

            # Count by source
            for source in ioc.sources:
                self.by_source[source.tool] = self.by_source.get(source.tool, 0) + 1

    def get_by_type(self, ioc_type: IoCType) -> list[IoC]:
        """Get IoCs filtered by type."""
        return [ioc for ioc in self.iocs if ioc.type == ioc_type]

    def get_by_priority(self, min_priority: int = 1) -> list[IoC]:
        """Get IoCs with priority >= min_priority, sorted by priority desc."""
        filtered = [ioc for ioc in self.iocs if ioc.pyramid_priority >= min_priority]
        return sorted(filtered, key=lambda x: x.pyramid_priority, reverse=True)

    def get_by_source(self, source: str) -> list[IoC]:
        """Get IoCs from a specific source/tool."""
        return [
            ioc for ioc in self.iocs
            if any(s.tool == source for s in ioc.sources)
        ]


class TimelineEvent(BaseModel):
    """A significant event in the investigation timeline."""
    id: str = Field(default_factory=lambda: f"evt-{uuid.uuid4().hex[:8]}")
    timestamp: datetime
    event_type: str
    source: SourceType
    tool: str
    summary: str
    severity: Severity = Severity.INFO
    details: dict[str, Any] = Field(default_factory=dict)
    related_iocs: list[str] = Field(default_factory=list)
    mitre_technique: str | None = None
    host: str | None = None
    user: str | None = None
    raw_event_id: str | None = None


class SourceFindings(BaseModel):
    """Findings from a specific source/tool."""
    source: SourceType
    tool: str
    query_time: datetime = Field(default_factory=datetime.utcnow)
    query_description: str | None = None
    total_events: int = 0
    summary: dict[str, Any] = Field(default_factory=dict)
    key_findings: list[str] = Field(default_factory=list)
    iocs_extracted: int = 0
    events_kept: int = 0
    mitre_techniques: list[str] = Field(default_factory=list)
    raw_query: str | None = None


class InvestigationStatistics(BaseModel):
    """Statistics for an investigation."""
    total_iocs: int = 0
    total_events: int = 0
    affected_hosts: int = 0
    affected_users: int = 0
    mitre_techniques: int = 0
    sources_used: int = 0
    queries_executed: int = 0


class InvestigationManifest(BaseModel):
    """Metadata manifest for a single investigation."""
    id: str
    name: str
    description: str = ""
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    status: InvestigationStatus = InvestigationStatus.ACTIVE
    severity: Severity = Severity.UNKNOWN
    tags: list[str] = Field(default_factory=list)
    sources_used: list[str] = Field(default_factory=list)
    statistics: InvestigationStatistics = Field(default_factory=InvestigationStatistics)
    kill_chain_stages: list[str] = Field(default_factory=list)
    size_bytes: int = 0
    session_count: int = 1
    last_session_at: datetime = Field(default_factory=datetime.utcnow)
    resolution: str | None = None
    analyst_notes: list[str] = Field(default_factory=list)

    def update_timestamp(self) -> None:
        """Update the updated_at timestamp."""
        self.updated_at = datetime.utcnow()


class Investigation(BaseModel):
    """Complete investigation data structure."""
    manifest: InvestigationManifest
    iocs: IoCCollection
    timeline: list[TimelineEvent] = Field(default_factory=list)
    source_findings: dict[str, SourceFindings] = Field(default_factory=dict)

    @classmethod
    def create(cls, name: str, description: str = "", tags: list[str] = None) -> "Investigation":
        """Create a new investigation."""
        inv_id = f"INV-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
        manifest = InvestigationManifest(
            id=inv_id,
            name=name,
            description=description,
            tags=tags or [],
        )
        iocs = IoCCollection(investigation_id=inv_id)
        return cls(manifest=manifest, iocs=iocs)

    def add_timeline_event(self, event: TimelineEvent) -> None:
        """Add a timeline event and sort by timestamp."""
        self.timeline.append(event)
        self.timeline.sort(key=lambda x: x.timestamp)
        self.manifest.update_timestamp()

    def add_source_findings(self, findings: SourceFindings) -> None:
        """Add findings from a source."""
        key = f"{findings.source.value}_{findings.tool}"
        if key in self.source_findings:
            # Merge with existing
            existing = self.source_findings[key]
            existing.total_events += findings.total_events
            existing.iocs_extracted += findings.iocs_extracted
            existing.key_findings.extend(findings.key_findings)
            existing.mitre_techniques = list(
                set(existing.mitre_techniques + findings.mitre_techniques)
            )
        else:
            self.source_findings[key] = findings

        # Update manifest
        if findings.source.value not in self.manifest.sources_used:
            self.manifest.sources_used.append(findings.source.value)
        self.manifest.statistics.queries_executed += 1
        self.manifest.update_timestamp()


class IndexEntry(BaseModel):
    """Entry in the master index for quick lookup."""
    id: str
    name: str
    created_at: datetime
    updated_at: datetime
    status: InvestigationStatus
    severity: Severity
    size_bytes: int
    ioc_count: int
    sources: list[str]
    tags: list[str] = Field(default_factory=list)


class MasterIndex(BaseModel):
    """Master index of all investigations."""
    version: str = "1.0.0"
    last_updated: datetime = Field(default_factory=datetime.utcnow)
    total_investigations: int = 0
    total_size_bytes: int = 0
    max_size_bytes: int = 8 * 1024 * 1024 * 1024  # 8GB default
    investigations: list[IndexEntry] = Field(default_factory=list)

    def add_investigation(self, manifest: InvestigationManifest) -> None:
        """Add or update an investigation in the index."""
        entry = IndexEntry(
            id=manifest.id,
            name=manifest.name,
            created_at=manifest.created_at,
            updated_at=manifest.updated_at,
            status=manifest.status,
            severity=manifest.severity,
            size_bytes=manifest.size_bytes,
            ioc_count=manifest.statistics.total_iocs,
            sources=manifest.sources_used,
            tags=manifest.tags,
        )

        # Update or add
        for i, existing in enumerate(self.investigations):
            if existing.id == entry.id:
                self.investigations[i] = entry
                self._update_totals()
                return

        self.investigations.append(entry)
        self._update_totals()

    def remove_investigation(self, investigation_id: str) -> IndexEntry | None:
        """Remove an investigation from the index."""
        for i, entry in enumerate(self.investigations):
            if entry.id == investigation_id:
                removed = self.investigations.pop(i)
                self._update_totals()
                return removed
        return None

    def _update_totals(self) -> None:
        """Update total counts."""
        self.total_investigations = len(self.investigations)
        self.total_size_bytes = sum(inv.size_bytes for inv in self.investigations)
        self.last_updated = datetime.utcnow()

    def get_recent(self, limit: int = 10, status: InvestigationStatus | None = None) -> list[IndexEntry]:
        """Get recent investigations, optionally filtered by status."""
        filtered = self.investigations
        if status:
            filtered = [inv for inv in filtered if inv.status == status]

        # Sort by updated_at descending
        sorted_inv = sorted(filtered, key=lambda x: x.updated_at, reverse=True)
        return sorted_inv[:limit]

    def get_oldest(self) -> IndexEntry | None:
        """Get the oldest investigation (for FIFO)."""
        if not self.investigations:
            return None
        return min(self.investigations, key=lambda x: x.updated_at)
