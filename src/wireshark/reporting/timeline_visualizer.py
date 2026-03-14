# src/wireshark/reporting/timeline_visualizer.py
"""ASCII timeline visualization for network analysis."""
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

# Kill chain stage colors/prefixes for ASCII display
KILL_CHAIN_STAGES = {
    "reconnaissance": "[RECON]",
    "weaponization": "[WEAPON]",
    "delivery": "[DELIVER]",
    "exploitation": "[EXPLOIT]",
    "installation": "[INSTALL]",
    "command_and_control": "[C2]",
    "c2": "[C2]",
    "actions_on_objectives": "[ACTION]",
}


class TimelineVisualizer:
    """Generate ASCII timeline visualizations."""

    def __init__(self, width: int = 80):
        """Initialize timeline visualizer.

        Args:
            width: Terminal width for rendering
        """
        self.width = width
        self._bar_char = "█"
        self._empty_char = "░"
        self._event_char = "●"
        self._line_char = "─"

    def format_bytes(self, bytes_value: int) -> str:
        """Format bytes in human-readable format.

        Args:
            bytes_value: Bytes count

        Returns:
            Human-readable string (e.g., "1.5 GB")
        """
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if bytes_value < 1024.0:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.1f} PB"

    def generate_beaconing_timeline(
        self,
        beacon_events: List[Dict],
        target_ip: str,
        time_range_hours: int = 24
    ) -> str:
        """Generate ASCII beaconing timeline.

        Args:
            beacon_events: List of beacon event dictionaries
            target_ip: Target IP being beaconed
            time_range_hours: Time range to visualize

        Returns:
            ASCII timeline string
        """
        if not beacon_events:
            return "No beacon events to display."

        lines = []
        lines.append("═" * self.width)
        lines.append(f" BEACONING ANALYSIS: {target_ip}")
        lines.append("═" * self.width)
        lines.append("")

        # Calculate interval statistics
        timestamps = sorted([e.get("timestamp", 0) for e in beacon_events])
        if len(timestamps) > 1:
            intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
            mean_interval = sum(intervals) / len(intervals)
            variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
            std_dev = variance ** 0.5
            jitter = (std_dev / mean_interval * 100) if mean_interval > 0 else 0

            lines.append(f" Interval Analysis: Mean={mean_interval:.1f}s, StdDev={std_dev:.1f}s, Jitter={jitter:.1f}%")
            lines.append("")

        # Generate timeline bar
        min_ts = min(timestamps)
        max_ts = max(timestamps)
        time_span = max(max_ts - min_ts, 1)

        # Create timeline header
        bar_width = self.width - 20
        lines.append(f" Timeline ({time_range_hours}h):")

        # Build the timeline bar
        timeline_bar = [self._line_char] * bar_width
        for ts in timestamps:
            pos = int((ts - min_ts) / time_span * (bar_width - 1))
            pos = max(0, min(pos, bar_width - 1))
            timeline_bar[pos] = self._event_char

        # Format source IPs
        source_ips = set(e.get("src_ip", "unknown") for e in beacon_events)
        for src_ip in list(source_ips)[:3]:
            lines.append(f" {src_ip:15} {''.join(timeline_bar)}")

        lines.append("")
        lines.append(f" Legend: {self._event_char} = Connection event")
        lines.append("")
        lines.append("═" * self.width)

        return "\n".join(lines)

    def generate_volume_chart(
        self,
        volume_data: List[Dict],
        bar_width: int = 30
    ) -> str:
        """Generate volume over time chart.

        Args:
            volume_data: List of {hour, bytes} dictionaries
            bar_width: Width of volume bars

        Returns:
            ASCII volume chart
        """
        if not volume_data:
            return "No volume data to display."

        lines = []
        lines.append(" Volume Over Time:")
        lines.append("")

        max_bytes = max(d.get("bytes", 0) for d in volume_data)
        if max_bytes == 0:
            max_bytes = 1

        for entry in volume_data:
            hour = entry.get("hour", "??:??")
            bytes_val = entry.get("bytes", 0)
            ratio = bytes_val / max_bytes

            filled = int(ratio * bar_width)
            empty = bar_width - filled

            bar = self._bar_char * filled + self._empty_char * empty
            formatted = self.format_bytes(bytes_val)

            lines.append(f" {hour} {bar}  {formatted}")

        return "\n".join(lines)

    def generate_connection_timeline(
        self,
        connections: List[Dict]
    ) -> str:
        """Generate connection timeline.

        Args:
            connections: List of connection dictionaries

        Returns:
            ASCII connection timeline
        """
        if not connections:
            return "No connections to display."

        lines = []
        lines.append(" CONNECTION TIMELINE")
        lines.append("═" * 60)
        lines.append("")

        # Group by source IP
        by_source = {}
        for conn in connections:
            src = conn.get("src_ip", "unknown")
            by_source.setdefault(src, []).append(conn)

        for src_ip, conns in by_source.items():
            lines.append(f" Source: {src_ip}")

            for conn in conns[:5]:  # Limit to 5 per source
                ts = conn.get("timestamp", 0)
                dst = conn.get("dst_ip", "?")
                event = conn.get("event", "connection")

                if isinstance(ts, (int, float)):
                    time_str = datetime.fromtimestamp(ts).strftime("%H:%M:%S")
                else:
                    time_str = str(ts)

                lines.append(f"   [{time_str}] {self._line_char*3}> {dst} ({event})")

            if len(conns) > 5:
                lines.append(f"   ... and {len(conns) - 5} more connections")

            lines.append("")

        lines.append("═" * 60)

        return "\n".join(lines)

    def generate_attack_stage_timeline(
        self,
        events: List[Dict]
    ) -> str:
        """Generate kill chain stage timeline.

        Args:
            events: List of stage event dictionaries

        Returns:
            ASCII attack stage timeline
        """
        if not events:
            return "No attack stage events to display."

        lines = []
        lines.append(" ATTACK STAGE TIMELINE (Cyber Kill Chain)")
        lines.append("═" * 60)
        lines.append("")

        # Sort by timestamp
        sorted_events = sorted(events, key=lambda x: x.get("timestamp", 0))

        for event in sorted_events:
            ts = event.get("timestamp", 0)
            stage = event.get("stage", "unknown").lower()
            description = event.get("description", "")

            if isinstance(ts, (int, float)):
                time_str = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
            else:
                time_str = str(ts)

            stage_label = KILL_CHAIN_STAGES.get(stage, f"[{stage.upper()[:6]}]")
            lines.append(f" {time_str}  {stage_label:10} {description}")

        lines.append("")
        lines.append("═" * 60)

        return "\n".join(lines)

    def generate_lateral_movement_graph(
        self,
        movements: List[Dict]
    ) -> str:
        """Generate lateral movement graph.

        Args:
            movements: List of lateral movement dictionaries

        Returns:
            ASCII representation of lateral movement
        """
        if not movements:
            return "No lateral movement detected."

        lines = []
        lines.append(" LATERAL MOVEMENT MAP")
        lines.append("═" * 60)
        lines.append("")

        # Group by source
        by_source = {}
        for mov in movements:
            src = mov.get("src_ip", "unknown")
            by_source.setdefault(src, []).append(mov)

        for src_ip, movs in by_source.items():
            lines.append(f" [{src_ip}]")

            for mov in movs:
                dst = mov.get("dst_ip", "?")
                mov_type = mov.get("movement_type", "unknown")
                lines.append(f"      │")
                lines.append(f"      └──({mov_type})──> [{dst}]")

            lines.append("")

        lines.append("═" * 60)

        return "\n".join(lines)

    def generate_summary_dashboard(
        self,
        stats: Dict[str, Any]
    ) -> str:
        """Generate summary dashboard.

        Args:
            stats: Statistics dictionary

        Returns:
            ASCII dashboard
        """
        lines = []
        lines.append("╔" + "═" * (self.width - 2) + "╗")
        lines.append("║" + " NETWORK ANALYSIS SUMMARY".center(self.width - 2) + "║")
        lines.append("╠" + "═" * (self.width - 2) + "╣")

        # Format stats
        stat_items = [
            ("Total Packets", stats.get("total_packets", 0)),
            ("Unique IPs", stats.get("unique_ips", 0)),
            ("Beacons Detected", stats.get("beacons_detected", 0)),
            ("Anomalies Found", stats.get("anomalies_found", 0)),
            ("IoCs Extracted", stats.get("iocs_extracted", 0)),
        ]

        for label, value in stat_items:
            line = f" {label}: {value}"
            lines.append("║" + line.ljust(self.width - 2) + "║")

        lines.append("╚" + "═" * (self.width - 2) + "╝")

        return "\n".join(lines)
