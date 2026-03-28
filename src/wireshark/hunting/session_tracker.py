# src/wireshark/hunting/session_tracker.py
"""TCP/UDP session reconstruction and tracking."""

import logging
from collections import defaultdict
from datetime import datetime
from typing import Any

from src.wireshark.models import Session

logger = logging.getLogger(__name__)

# TCP flag bit positions
TCP_FLAGS = {
    0x001: "FIN",
    0x002: "SYN",
    0x004: "RST",
    0x008: "PSH",
    0x010: "ACK",
    0x020: "URG",
    0x040: "ECE",
    0x080: "CWR",
}


class SessionTracker:
    """Track and reconstruct TCP/UDP sessions from packet data."""

    def __init__(self):
        """Initialize session tracker."""

    def build_sessions_from_packets(self, packets: list[dict], protocol: str = "tcp") -> list[Session]:
        """Build session objects from packet list.

        Args:
            packets: List of packet dictionaries with stream info
            protocol: Protocol type (tcp or udp)

        Returns:
            List of Session objects
        """
        if not packets:
            return []

        # Group packets by stream ID
        streams = defaultdict(list)
        stream_field = f"{protocol}.stream"

        for pkt in packets:
            stream_id = pkt.get(stream_field)
            if stream_id is not None:
                streams[stream_id].append(pkt)

        sessions = []
        for stream_id, stream_packets in streams.items():
            session = self._build_single_session(stream_id=int(stream_id), packets=stream_packets, protocol=protocol)
            if session:
                sessions.append(session)

        return sessions

    def _build_single_session(self, stream_id: int, packets: list[dict], protocol: str) -> Session | None:
        """Build a single session from its packets.

        Args:
            stream_id: Stream identifier
            packets: Packets belonging to this stream
            protocol: Protocol type

        Returns:
            Session object or None
        """
        if not packets:
            return None

        # Sort packets by timestamp
        sorted_packets = sorted(packets, key=lambda p: float(p.get("frame.time_epoch", 0)))

        # Determine client (initiator) - first packet's source
        first_pkt = sorted_packets[0]
        last_pkt = sorted_packets[-1]

        # For TCP, check SYN flag to identify initiator
        initiator_ip = first_pkt.get("ip.src")
        initiator_port = first_pkt.get(f"{protocol}.srcport")
        responder_ip = first_pkt.get("ip.dst")
        responder_port = first_pkt.get(f"{protocol}.dstport")

        # If first packet has SYN flag, it's definitely the initiator
        if protocol == "tcp":
            flags_hex = first_pkt.get("tcp.flags", "0x0")
            try:
                flags_int = int(flags_hex, 16) if isinstance(flags_hex, str) else int(flags_hex)
                if not (flags_int & 0x002):  # Not SYN
                    # Try to find the SYN packet
                    for pkt in sorted_packets[:5]:  # Check first few packets
                        pkt_flags = pkt.get("tcp.flags", "0x0")
                        pkt_flags_int = int(pkt_flags, 16) if isinstance(pkt_flags, str) else int(pkt_flags)
                        if pkt_flags_int & 0x002 and not (pkt_flags_int & 0x010):  # SYN but not ACK
                            initiator_ip = pkt.get("ip.src")
                            initiator_port = pkt.get(f"{protocol}.srcport")
                            responder_ip = pkt.get("ip.dst")
                            responder_port = pkt.get(f"{protocol}.dstport")
                            break
            except (ValueError, TypeError):
                pass

        # Calculate statistics
        total_bytes = sum(int(p.get("frame.len", 0)) for p in sorted_packets)
        packet_count = len(sorted_packets)

        # Extract timestamps
        try:
            start_time = datetime.fromtimestamp(float(first_pkt.get("frame.time_epoch", 0)))
            end_time = datetime.fromtimestamp(float(last_pkt.get("frame.time_epoch", 0)))
        except (ValueError, TypeError, OSError):
            start_time = datetime.now()
            end_time = datetime.now()

        # Extract TCP flags seen in session
        flags_seen = set()
        if protocol == "tcp":
            for pkt in sorted_packets:
                flags_hex = pkt.get("tcp.flags", "0x0")
                try:
                    flags_int = int(flags_hex, 16) if isinstance(flags_hex, str) else int(flags_hex)
                    for bit, name in TCP_FLAGS.items():
                        if flags_int & bit:
                            flags_seen.add(name)
                except (ValueError, TypeError):
                    pass

        # Convert ports to int
        try:
            src_port = int(initiator_port) if initiator_port else 0
            dst_port = int(responder_port) if responder_port else 0
        except (ValueError, TypeError):
            src_port = 0
            dst_port = 0

        return Session(
            stream_id=stream_id,
            protocol=protocol,
            src_ip=initiator_ip or "unknown",
            src_port=src_port,
            dst_ip=responder_ip or "unknown",
            dst_port=dst_port,
            start_time=start_time,
            end_time=end_time,
            packet_count=packet_count,
            byte_count=total_bytes,
            flags=sorted(list(flags_seen)),
        )

    def track_from_pcap(
        self, pcap_path: str, protocol: str = "tcp", display_filter: str | None = None, executor=None
    ) -> list[Session]:
        """Track sessions from a PCAP file.

        Args:
            pcap_path: Path to PCAP file
            protocol: Protocol to track (tcp or udp)
            display_filter: Optional display filter
            executor: Optional TSharkExecutor instance

        Returns:
            List of Session objects
        """
        from src.wireshark.core.tshark_executor import TSharkExecutor

        if executor is None:
            executor = TSharkExecutor()

        # Build field list based on protocol
        stream_field = f"{protocol}.stream"
        srcport_field = f"{protocol}.srcport"
        dstport_field = f"{protocol}.dstport"

        fields = [stream_field, "ip.src", "ip.dst", srcport_field, dstport_field, "frame.time_epoch", "frame.len"]

        if protocol == "tcp":
            fields.append("tcp.flags")

        # Build filter
        if display_filter:
            filter_str = f"({protocol}) and ({display_filter})"
        else:
            filter_str = protocol

        results = executor.execute_and_parse_fields(
            pcap_path=pcap_path, fields=fields, display_filter=filter_str, timeout=300
        )

        return self.build_sessions_from_packets(results, protocol)

    def track_all_sessions(self, pcap_path: str, executor=None) -> list[Session]:
        """Track both TCP and UDP sessions from a PCAP.

        Args:
            pcap_path: Path to PCAP file
            executor: Optional TSharkExecutor instance

        Returns:
            List of all Session objects
        """
        sessions = []

        # Track TCP sessions
        tcp_sessions = self.track_from_pcap(pcap_path, "tcp", executor=executor)
        sessions.extend(tcp_sessions)

        # Track UDP sessions
        udp_sessions = self.track_from_pcap(pcap_path, "udp", executor=executor)
        sessions.extend(udp_sessions)

        return sessions

    def filter_by_port(self, sessions: list[Session], ports: list[int], check_both: bool = True) -> list[Session]:
        """Filter sessions by port number.

        Args:
            sessions: List of sessions to filter
            ports: List of port numbers to match
            check_both: Check both source and destination ports

        Returns:
            Filtered list of sessions
        """
        port_set = set(ports)
        filtered = []

        for session in sessions:
            if session.dst_port in port_set or check_both and session.src_port in port_set:
                filtered.append(session)

        return filtered

    def filter_by_ip(self, sessions: list[Session], ips: list[str], check_both: bool = True) -> list[Session]:
        """Filter sessions by IP address.

        Args:
            sessions: List of sessions to filter
            ips: List of IP addresses to match
            check_both: Check both source and destination IPs

        Returns:
            Filtered list of sessions
        """
        ip_set = set(ips)
        filtered = []

        for session in sessions:
            if session.dst_ip in ip_set or check_both and session.src_ip in ip_set:
                filtered.append(session)

        return filtered

    def get_session_summary(self, sessions: list[Session]) -> dict[str, Any]:
        """Get summary statistics for a list of sessions.

        Args:
            sessions: List of sessions

        Returns:
            Summary dictionary
        """
        if not sessions:
            return {
                "total_sessions": 0,
                "tcp_sessions": 0,
                "udp_sessions": 0,
                "total_packets": 0,
                "total_bytes": 0,
                "unique_src_ips": 0,
                "unique_dst_ips": 0,
                "unique_dst_ports": 0,
            }

        tcp_sessions = [s for s in sessions if s.protocol == "tcp"]
        udp_sessions = [s for s in sessions if s.protocol == "udp"]

        return {
            "total_sessions": len(sessions),
            "tcp_sessions": len(tcp_sessions),
            "udp_sessions": len(udp_sessions),
            "total_packets": sum(s.packet_count for s in sessions),
            "total_bytes": sum(s.byte_count for s in sessions),
            "unique_src_ips": len(set(s.src_ip for s in sessions)),
            "unique_dst_ips": len(set(s.dst_ip for s in sessions)),
            "unique_dst_ports": len(set(s.dst_port for s in sessions)),
        }

    def find_long_sessions(self, sessions: list[Session], min_duration_seconds: float = 300) -> list[Session]:
        """Find sessions that lasted longer than threshold.

        Args:
            sessions: List of sessions
            min_duration_seconds: Minimum duration in seconds

        Returns:
            Sessions longer than threshold
        """
        long_sessions = []

        for session in sessions:
            if session.end_time and session.start_time:
                duration = (session.end_time - session.start_time).total_seconds()
                if duration >= min_duration_seconds:
                    long_sessions.append(session)

        return long_sessions

    def find_high_volume_sessions(
        self,
        sessions: list[Session],
        min_bytes: int = 1048576,  # 1MB default
    ) -> list[Session]:
        """Find sessions with high data transfer.

        Args:
            sessions: List of sessions
            min_bytes: Minimum bytes threshold

        Returns:
            High volume sessions
        """
        return [s for s in sessions if s.byte_count >= min_bytes]
