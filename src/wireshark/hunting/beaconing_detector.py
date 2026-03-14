# src/wireshark/hunting/beaconing_detector.py
"""C2 beaconing pattern detection with ASCII timeline visualization."""
import logging
import statistics
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple

from src.wireshark.models import BeaconPattern
from src.wireshark.baseline.defaults import DEFAULT_BASELINE, get_threshold

logger = logging.getLogger(__name__)


class BeaconingDetector:
    """Detect C2 beaconing patterns in network traffic."""

    def __init__(self, baseline: Optional[Dict] = None):
        """Initialize detector with optional custom baseline."""
        self.baseline = baseline or DEFAULT_BASELINE

    def analyze_intervals(self, timestamps: List[float]) -> Dict[str, Any]:
        """Analyze time intervals between connections.

        Args:
            timestamps: List of epoch timestamps (sorted)

        Returns:
            Dictionary with interval statistics
        """
        if len(timestamps) < 2:
            return {
                "mean_interval": 0,
                "stddev": 0,
                "jitter_percent": 100,
                "interval_count": 0
            }

        # Sort timestamps
        sorted_ts = sorted(timestamps)

        # Calculate intervals
        intervals = []
        for i in range(1, len(sorted_ts)):
            interval = sorted_ts[i] - sorted_ts[i - 1]
            intervals.append(interval)

        if not intervals:
            return {
                "mean_interval": 0,
                "stddev": 0,
                "jitter_percent": 100,
                "interval_count": 0
            }

        mean_interval = statistics.mean(intervals)
        stddev = statistics.stdev(intervals) if len(intervals) > 1 else 0

        # Calculate jitter as coefficient of variation
        jitter_percent = (stddev / mean_interval * 100) if mean_interval > 0 else 100

        return {
            "mean_interval": mean_interval,
            "stddev": stddev,
            "jitter_percent": jitter_percent,
            "interval_count": len(intervals),
            "min_interval": min(intervals),
            "max_interval": max(intervals),
            "intervals": intervals
        }

    def detect_patterns(
        self,
        connections: List[Dict],
        min_count: Optional[int] = None,
        max_jitter: Optional[float] = None
    ) -> List[BeaconPattern]:
        """Detect beaconing patterns from connection data.

        Args:
            connections: List of connection dicts with timestamp, src_ip, dst_ip, dst_port
            min_count: Minimum connections to consider (default from baseline)
            max_jitter: Maximum jitter percentage to flag as beaconing (default from baseline)

        Returns:
            List of detected BeaconPattern objects
        """
        if min_count is None:
            min_count = get_threshold("min_beacon_count", self.baseline) or 5

        if max_jitter is None:
            tolerance = get_threshold("beacon_interval_tolerance", self.baseline) or 0.15
            max_jitter = tolerance * 100  # Convert to percentage

        # Group connections by (src_ip, dst_ip, dst_port)
        groups = defaultdict(list)
        for conn in connections:
            key = (conn["src_ip"], conn["dst_ip"], conn["dst_port"])
            groups[key].append(conn["timestamp"])

        patterns = []
        for (src_ip, dst_ip, dst_port), timestamps in groups.items():
            if len(timestamps) < min_count:
                continue

            # Analyze intervals
            stats = self.analyze_intervals(timestamps)

            # Check if this looks like beaconing
            if stats["jitter_percent"] <= max_jitter:
                # Determine confidence based on sample size and jitter
                confidence = self._calculate_confidence(
                    len(timestamps),
                    stats["jitter_percent"],
                    stats["mean_interval"]
                )

                # Create datetime objects for timestamps
                sorted_ts = sorted(timestamps)
                dt_timestamps = [
                    datetime.fromtimestamp(ts) if isinstance(ts, (int, float)) else ts
                    for ts in sorted_ts
                ]

                pattern = BeaconPattern(
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    dest_port=dst_port,
                    interval_mean_seconds=stats["mean_interval"],
                    interval_stddev=stats["stddev"],
                    jitter_percent=stats["jitter_percent"],
                    occurrence_count=len(timestamps),
                    confidence=confidence,
                    timestamps=dt_timestamps
                )
                patterns.append(pattern)

        # Sort by confidence (HIGH first)
        confidence_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        patterns.sort(key=lambda p: confidence_order.get(p.confidence, 3))

        return patterns

    def _calculate_confidence(
        self,
        sample_count: int,
        jitter_percent: float,
        mean_interval: float
    ) -> str:
        """Calculate confidence level for beaconing detection.

        Args:
            sample_count: Number of samples
            jitter_percent: Jitter percentage
            mean_interval: Mean interval in seconds

        Returns:
            Confidence level: HIGH, MEDIUM, or LOW
        """
        min_interval = get_threshold("beacon_min_interval", self.baseline) or 10
        max_interval = get_threshold("beacon_max_interval", self.baseline) or 3600

        score = 0

        # Sample count scoring
        if sample_count >= 50:
            score += 3
        elif sample_count >= 20:
            score += 2
        elif sample_count >= 10:
            score += 1

        # Jitter scoring (lower is better)
        if jitter_percent <= 5:
            score += 3
        elif jitter_percent <= 10:
            score += 2
        elif jitter_percent <= 15:
            score += 1

        # Interval range scoring (typical C2 intervals)
        if min_interval <= mean_interval <= max_interval:
            score += 1

        # Determine confidence
        if score >= 5:
            return "HIGH"
        elif score >= 3:
            return "MEDIUM"
        else:
            return "LOW"

    def generate_ascii_timeline(
        self,
        pattern: BeaconPattern,
        width: int = 80
    ) -> str:
        """Generate ASCII timeline visualization for a beaconing pattern.

        Args:
            pattern: BeaconPattern object
            width: Width of the timeline in characters

        Returns:
            ASCII art timeline string
        """
        lines = []

        # Header
        header = "═" * width
        lines.append(header)
        lines.append(f" BEACONING ANALYSIS: {pattern.dest_ip}:{pattern.dest_port} (Confidence: {pattern.confidence})")
        lines.append(header)
        lines.append("")

        # Source info
        lines.append(f" Source: {pattern.source_ip}")
        lines.append(f" Destination: {pattern.dest_ip}:{pattern.dest_port}")
        lines.append("")

        # Interval analysis
        lines.append(f" Interval Analysis:")
        lines.append(f"   Mean: {pattern.interval_mean_seconds:.1f}s")
        lines.append(f"   StdDev: {pattern.interval_stddev:.1f}s")
        lines.append(f"   Jitter: {pattern.jitter_percent:.1f}%")
        lines.append(f"   Samples: {pattern.occurrence_count}")
        lines.append("")

        # Timeline visualization (if we have timestamps)
        if pattern.timestamps:
            lines.append(" Timeline:")

            # Get time range
            first_ts = pattern.timestamps[0]
            last_ts = pattern.timestamps[-1]

            if isinstance(first_ts, datetime):
                total_seconds = (last_ts - first_ts).total_seconds()
            else:
                total_seconds = last_ts - first_ts

            if total_seconds > 0:
                # Create timeline bar
                bar_width = width - 10
                bar = [" "] * bar_width

                # Mark each beacon occurrence
                for ts in pattern.timestamps:
                    if isinstance(ts, datetime):
                        offset = (ts - first_ts).total_seconds()
                    else:
                        offset = ts - first_ts

                    pos = int((offset / total_seconds) * (bar_width - 1))
                    pos = min(pos, bar_width - 1)
                    bar[pos] = "│"

                lines.append(f"   [{''.join(bar)}]")

                # Time labels
                if isinstance(first_ts, datetime):
                    start_label = first_ts.strftime("%H:%M")
                    end_label = last_ts.strftime("%H:%M")
                else:
                    start_label = f"{first_ts:.0f}s"
                    end_label = f"{last_ts:.0f}s"

                spacing = bar_width - len(start_label) - len(end_label) + 2
                lines.append(f"    {start_label}{' ' * spacing}{end_label}")
        else:
            lines.append(f" (No timestamp data available for visualization)")

        lines.append("")
        lines.append(header)

        return "\n".join(lines)

    def detect_from_pcap(
        self,
        pcap_path: str,
        executor=None
    ) -> List[BeaconPattern]:
        """Detect beaconing patterns from a PCAP file.

        Args:
            pcap_path: Path to PCAP file
            executor: Optional TSharkExecutor instance

        Returns:
            List of detected BeaconPattern objects
        """
        from src.wireshark.core.tshark_executor import TSharkExecutor

        if executor is None:
            executor = TSharkExecutor()

        # Extract connection data
        results = executor.execute_and_parse_fields(
            pcap_path=pcap_path,
            fields=["frame.time_epoch", "ip.src", "ip.dst", "tcp.dstport", "udp.dstport"],
            display_filter="tcp or udp",
            timeout=300
        )

        # Build connection list
        connections = []
        for row in results:
            timestamp = row.get("frame.time_epoch")
            src_ip = row.get("ip.src")
            dst_ip = row.get("ip.dst")
            dst_port = row.get("tcp.dstport") or row.get("udp.dstport")

            if timestamp and src_ip and dst_ip and dst_port:
                try:
                    connections.append({
                        "timestamp": float(timestamp),
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "dst_port": int(dst_port)
                    })
                except (ValueError, TypeError):
                    continue

        return self.detect_patterns(connections)
