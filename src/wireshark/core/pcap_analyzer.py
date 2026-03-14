# src/wireshark/core/pcap_analyzer.py
"""PCAP file analyzer using TShark."""
import hashlib
import logging
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from src.wireshark.core.tshark_executor import TSharkExecutor
from src.wireshark.models import (
    PcapMetadata, TopTalker, ProtocolStats, Session
)

logger = logging.getLogger(__name__)


class PcapAnalyzer:
    """Analyze PCAP files using TShark."""

    def __init__(self, executor: Optional[TSharkExecutor] = None):
        """Initialize analyzer with optional custom executor."""
        self.executor = executor or TSharkExecutor()

    def validate_pcap(self, pcap_path: str) -> Path:
        """Validate pcap file exists and is readable.

        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If file is not a valid pcap
        """
        path = Path(pcap_path)
        if not path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")
        if not path.is_file():
            raise ValueError(f"Not a file: {pcap_path}")
        return path

    def _compute_file_hash(self, pcap_path: str) -> str:
        """Compute SHA256 hash of file."""
        sha256 = hashlib.sha256()
        with open(pcap_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    def get_metadata(self, pcap_path: str) -> PcapMetadata:
        """Get metadata about a PCAP file.

        Args:
            pcap_path: Path to pcap file

        Returns:
            PcapMetadata object with file information
        """
        path = self.validate_pcap(pcap_path)

        # Get file size
        file_size = path.stat().st_size

        # Get file hash
        file_hash = self._compute_file_hash(pcap_path)

        # Get total packet count using io,stat
        count_cmd = [self.executor.tshark_path, "-r", pcap_path, "-q", "-z", "io,stat,0"]
        returncode, count_stdout, _ = self.executor.execute(count_cmd, timeout=120)

        packet_count = 0
        if returncode == 0:
            # Parse io,stat output for total frames
            for line in count_stdout.split("\n"):
                if "|" in line and "Frames" not in line and "Interval" not in line:
                    parts = line.split("|")
                    if len(parts) >= 2:
                        try:
                            # Try to parse the frames column
                            frame_str = parts[1].strip()
                            if frame_str.isdigit():
                                packet_count = int(frame_str)
                        except (ValueError, IndexError):
                            pass

        # Get first packet timestamp
        first_cmd = self.executor.build_command(
            pcap_path=pcap_path,
            fields=["frame.time_epoch"],
            limit=1
        )
        _, first_out, _ = self.executor.execute(first_cmd, timeout=60)

        # Parse timestamps
        time_start = datetime.now()
        time_end = datetime.now()

        try:
            if first_out.strip():
                first_epoch = float(first_out.strip().split("\n")[0])
                time_start = datetime.fromtimestamp(first_epoch)
        except (ValueError, IndexError):
            pass

        # Get last packet timestamp - read all timestamps and take the last one
        # More reliable than trying to get specific packet number
        all_ts_cmd = self.executor.build_command(
            pcap_path=pcap_path,
            fields=["frame.time_epoch"]
        )
        _, all_ts_out, _ = self.executor.execute(all_ts_cmd, timeout=180)

        try:
            timestamps = [line.strip() for line in all_ts_out.strip().split("\n") if line.strip()]
            if timestamps:
                last_epoch = float(timestamps[-1])
                time_end = datetime.fromtimestamp(last_epoch)
                # Update packet count from actual count
                if len(timestamps) > packet_count:
                    packet_count = len(timestamps)
        except (ValueError, IndexError):
            time_end = time_start

        duration = (time_end - time_start).total_seconds()

        # Get protocols
        protocols = self.get_protocol_list(pcap_path)

        return PcapMetadata(
            file_path=pcap_path,
            file_size_bytes=file_size,
            file_hash_sha256=file_hash,
            packet_count=packet_count,
            time_start=time_start,
            time_end=time_end,
            duration_seconds=duration,
            protocols_detected=protocols
        )

    def get_protocol_list(self, pcap_path: str) -> List[str]:
        """Get list of protocols detected in pcap."""
        cmd = self.executor.build_stats_command(pcap_path, "io,phs")
        returncode, stdout, _ = self.executor.execute(cmd, timeout=120)

        protocols = []
        if returncode == 0:
            for line in stdout.split("\n"):
                # Parse protocol hierarchy output
                match = re.match(r"\s*(\w+)\s*frames:", line)
                if match:
                    protocols.append(match.group(1).lower())

        return list(set(protocols))

    def get_protocol_hierarchy(self, pcap_path: str) -> List[ProtocolStats]:
        """Get protocol hierarchy statistics.

        Returns:
            List of ProtocolStats objects
        """
        self.validate_pcap(pcap_path)

        cmd = self.executor.build_stats_command(pcap_path, "io,phs")
        returncode, stdout, stderr = self.executor.execute(cmd, timeout=120)

        stats = []
        if returncode != 0:
            logger.error(f"Failed to get protocol hierarchy: {stderr}")
            return stats

        # Parse protocol hierarchy statistics
        # Format: "  eth  frames:12345  bytes:6789012"
        for line in stdout.split("\n"):
            match = re.match(r"\s*(\S+)\s+frames:(\d+)\s+bytes:(\d+)", line)
            if match:
                protocol = match.group(1)
                frames = int(match.group(2))
                bytes_count = int(match.group(3))
                stats.append(ProtocolStats(
                    protocol=protocol,
                    packet_count=frames,
                    byte_count=bytes_count,
                    percentage=0.0  # Calculate later
                ))

        # Calculate percentages
        total_packets = sum(s.packet_count for s in stats) if stats else 1
        for stat in stats:
            stat.percentage = (stat.packet_count / total_packets) * 100

        return stats

    def get_top_talkers(
        self,
        pcap_path: str,
        limit: int = 20
    ) -> List[TopTalker]:
        """Get top communicating hosts by packet count.

        Args:
            pcap_path: Path to pcap file
            limit: Maximum number of talkers to return

        Returns:
            List of TopTalker objects sorted by packet count
        """
        self.validate_pcap(pcap_path)

        # Get IP endpoints statistics
        cmd = self.executor.build_stats_command(pcap_path, "endpoints,ip")
        returncode, stdout, stderr = self.executor.execute(cmd, timeout=120)

        talkers = []
        if returncode != 0:
            logger.error(f"Failed to get top talkers: {stderr}")
            return talkers

        # Parse endpoints output
        # Format: "192.168.1.1    123    45678    67    89012"
        #         IP            Packets Bytes   TxPkts TxBytes
        in_data = False
        for line in stdout.split("\n"):
            if "Filter:" in line or "=" * 10 in line:
                in_data = True
                continue
            if not in_data:
                continue

            parts = line.split()
            if len(parts) >= 3:
                try:
                    ip = parts[0]
                    # Validate IP format
                    if not re.match(r"\d+\.\d+\.\d+\.\d+", ip):
                        continue
                    packets = int(parts[1])
                    bytes_count = int(parts[2]) if len(parts) > 2 else 0

                    # Check if internal
                    is_internal = (
                        ip.startswith("10.") or
                        ip.startswith("192.168.") or
                        ip.startswith("172.16.") or
                        ip.startswith("172.17.") or
                        ip.startswith("172.18.") or
                        ip.startswith("172.19.") or
                        ip.startswith("172.2") or
                        ip.startswith("172.30.") or
                        ip.startswith("172.31.")
                    )

                    talkers.append(TopTalker(
                        ip=ip,
                        packet_count=packets,
                        byte_count=bytes_count,
                        connection_count=0,  # Would need separate query
                        protocols=[],
                        is_internal=is_internal
                    ))
                except (ValueError, IndexError):
                    continue

        # Sort by packet count and limit
        talkers.sort(key=lambda x: x.packet_count, reverse=True)
        return talkers[:limit]

    def get_conversations(
        self,
        pcap_path: str,
        protocol: str = "tcp",
        limit: int = 50
    ) -> List[Dict]:
        """Get conversation statistics.

        Args:
            pcap_path: Path to pcap file
            protocol: Protocol to analyze (tcp, udp, ip)
            limit: Maximum conversations to return

        Returns:
            List of conversation dicts
        """
        self.validate_pcap(pcap_path)

        cmd = self.executor.build_stats_command(pcap_path, f"conv,{protocol}")
        returncode, stdout, stderr = self.executor.execute(cmd, timeout=120)

        conversations = []
        if returncode != 0:
            logger.error(f"Failed to get conversations: {stderr}")
            return conversations

        # Parse conversation output
        in_data = False
        for line in stdout.split("\n"):
            if "Filter:" in line or "=" * 10 in line:
                in_data = True
                continue
            if not in_data:
                continue

            # Parse line: "192.168.1.1:443 <-> 10.0.0.1:54321  123  45678  ..."
            if "<->" in line:
                parts = line.split()
                if len(parts) >= 4:
                    try:
                        src = parts[0]
                        dst = parts[2]
                        conversations.append({
                            "source": src,
                            "destination": dst,
                            "raw": line.strip()
                        })
                    except IndexError:
                        continue

        return conversations[:limit]

    def get_dns_queries(
        self,
        pcap_path: str,
        limit: int = 500
    ) -> List[Dict]:
        """Get DNS queries from pcap.

        Args:
            pcap_path: Path to pcap file
            limit: Maximum queries to return

        Returns:
            List of DNS query dicts
        """
        self.validate_pcap(pcap_path)

        results = self.executor.execute_and_parse_fields(
            pcap_path=pcap_path,
            fields=["dns.qry.name", "dns.qry.type", "dns.flags.rcode", "ip.src", "frame.time_epoch"],
            display_filter="dns.flags.response == 0",
            limit=limit
        )

        queries = []
        for row in results:
            if row.get("dns.qry.name"):
                queries.append({
                    "query_name": row.get("dns.qry.name", ""),
                    "query_type": row.get("dns.qry.type", ""),
                    "source_ip": row.get("ip.src", ""),
                    "timestamp": row.get("frame.time_epoch", "")
                })

        return queries

    def follow_stream(
        self,
        pcap_path: str,
        stream_type: str,
        stream_index: int,
        output_type: str = "ascii"
    ) -> str:
        """Follow and reconstruct a TCP/UDP stream.

        Args:
            pcap_path: Path to pcap file
            stream_type: tcp or udp
            stream_index: Stream index number
            output_type: ascii, hex, or raw

        Returns:
            Stream content as string
        """
        self.validate_pcap(pcap_path)

        cmd = self.executor.build_follow_stream_command(
            pcap_path=pcap_path,
            stream_type=stream_type,
            stream_index=stream_index,
            output_type=output_type
        )

        returncode, stdout, stderr = self.executor.execute(cmd, timeout=120)

        if returncode != 0:
            logger.error(f"Failed to follow stream: {stderr}")
            return ""

        return stdout
