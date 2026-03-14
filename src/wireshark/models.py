# src/wireshark/models.py
"""Data models for Wireshark network analysis module."""
from datetime import datetime
from enum import IntEnum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class PyramidLevel(IntEnum):
    """Pyramid of Pain levels for IoC prioritization."""
    HASH = 1        # Trivial to change
    IP = 2          # Easy to change
    DOMAIN = 3      # Simple to change
    ARTIFACTS = 4   # Annoying to change
    TOOLS = 5       # Challenging to change
    TTPS = 6        # Tough to change


class NetworkIoC(BaseModel):
    """Network-based Indicator of Compromise."""
    id: str
    type: str  # ip, domain, port, hash, user_agent, ja3, etc.
    value: str
    pyramid_level: PyramidLevel
    confidence: int = Field(ge=1, le=10)
    first_seen: datetime
    last_seen: datetime
    occurrence_count: int = Field(ge=1)
    source_tool: str
    context: Dict = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)


class PcapMetadata(BaseModel):
    """Metadata about analyzed PCAP file."""
    file_path: str
    file_size_bytes: int
    file_hash_sha256: str
    packet_count: int
    time_start: datetime
    time_end: datetime
    duration_seconds: float
    protocols_detected: List[str]


class TopTalker(BaseModel):
    """Top communicating host."""
    ip: str
    packet_count: int = 0
    byte_count: int = 0
    connection_count: int = 0
    protocols: List[str] = Field(default_factory=list)
    is_internal: bool = False


class ProtocolStats(BaseModel):
    """Protocol distribution statistics."""
    protocol: str
    packet_count: int
    byte_count: int
    percentage: float


class BeaconPattern(BaseModel):
    """Detected beaconing pattern."""
    source_ip: str
    dest_ip: str
    dest_port: int
    interval_mean_seconds: float
    interval_stddev: float
    jitter_percent: float
    occurrence_count: int
    confidence: str  # HIGH, MEDIUM, LOW
    timestamps: List[datetime] = Field(default_factory=list)


class Session(BaseModel):
    """Reconstructed network session."""
    stream_id: int
    protocol: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    start_time: datetime
    end_time: Optional[datetime] = None
    packet_count: int = 0
    byte_count: int = 0
    flags: List[str] = Field(default_factory=list)
    payload_preview: Optional[str] = None


class ExtractedObject(BaseModel):
    """Extracted network object."""
    id: str
    source_pcap: str
    protocol: str  # http, smb, ftp
    filename: str
    sha256: str
    size_bytes: int
    mime_type: Optional[str] = None
    source_ip: str
    dest_ip: str
    timestamp: datetime
    stored_locally: bool = False
    local_path: Optional[str] = None


class DnsQuery(BaseModel):
    """DNS query record."""
    query_name: str
    query_type: str
    response_code: Optional[str] = None
    response_addresses: List[str] = Field(default_factory=list)
    source_ip: str
    timestamp: datetime
    is_suspicious: bool = False
    suspicion_reason: Optional[str] = None


class AnomalyFinding(BaseModel):
    """Detected anomaly."""
    id: str
    type: str  # unusual_port, dns_tunnel, tls_no_sni, etc.
    severity: str  # critical, high, medium, low, info
    description: str
    source_ip: str
    dest_ip: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    evidence: Dict = Field(default_factory=dict)
    timestamp: datetime
    confidence: int = Field(ge=1, le=10)


class AnalysisResult(BaseModel):
    """Complete analysis result container."""
    pcap_metadata: PcapMetadata
    top_talkers: List[TopTalker] = Field(default_factory=list)
    protocol_stats: List[ProtocolStats] = Field(default_factory=list)
    anomalies: List[AnomalyFinding] = Field(default_factory=list)
    beacons: List[BeaconPattern] = Field(default_factory=list)
    sessions: List[Session] = Field(default_factory=list)
    iocs: List[NetworkIoC] = Field(default_factory=list)
    dns_queries: List[DnsQuery] = Field(default_factory=list)
    extracted_objects: List[ExtractedObject] = Field(default_factory=list)
