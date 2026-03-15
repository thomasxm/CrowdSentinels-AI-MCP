# src/wireshark/baseline/baseline_builder.py
"""Baseline builder for auto-learning from normal traffic."""
import logging
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from src.wireshark.baseline.defaults import DEFAULT_BASELINE, is_internal_ip
from src.wireshark.core.pcap_analyzer import PcapAnalyzer
from src.wireshark.core.tshark_executor import TSharkExecutor

logger = logging.getLogger(__name__)


class BaselineBuilder:
    """Build baselines from normal traffic captures."""

    def __init__(
        self,
        executor: TSharkExecutor | None = None,
        analyzer: PcapAnalyzer | None = None
    ):
        """Initialize baseline builder."""
        self.executor = executor or TSharkExecutor()
        self.analyzer = analyzer or PcapAnalyzer(self.executor)

    def build_from_pcap(
        self,
        pcap_path: str,
        name: str | None = None,
        include_defaults: bool = True
    ) -> dict[str, Any]:
        """Build baseline from a normal traffic PCAP.

        Args:
            pcap_path: Path to normal traffic pcap
            name: Optional name for the baseline
            include_defaults: Whether to include default legitimate ports

        Returns:
            Baseline dictionary
        """
        logger.info(f"Building baseline from: {pcap_path}")

        baseline = {
            "name": name or Path(pcap_path).stem,
            "source_pcap": pcap_path,
            "created_at": datetime.now().isoformat(),
            "observed_ports": {"tcp": [], "udp": []},
            "observed_ips": [],
            "observed_internal_ips": [],
            "observed_external_ips": [],
            "observed_protocols": [],
            "observed_dns_servers": [],
            "observed_domains": [],
            "traffic_stats": {}
        }

        # Get TCP ports
        tcp_ports = self._extract_ports(pcap_path, "tcp")
        baseline["observed_ports"]["tcp"] = tcp_ports

        # Get UDP ports
        udp_ports = self._extract_ports(pcap_path, "udp")
        baseline["observed_ports"]["udp"] = udp_ports

        # Get IP addresses
        ips = self._extract_ips(pcap_path)
        baseline["observed_ips"] = ips

        # Separate internal/external
        for ip in ips:
            if is_internal_ip(ip):
                baseline["observed_internal_ips"].append(ip)
            else:
                baseline["observed_external_ips"].append(ip)

        # Get protocols
        protocols = self._extract_protocols(pcap_path)
        baseline["observed_protocols"] = protocols

        # Get DNS servers (sources of DNS responses)
        dns_servers = self._extract_dns_servers(pcap_path)
        baseline["observed_dns_servers"] = dns_servers

        # Get queried domains
        domains = self._extract_domains(pcap_path)
        baseline["observed_domains"] = domains[:1000]  # Limit size

        # Include defaults if requested
        if include_defaults:
            baseline["legitimate_ports"] = DEFAULT_BASELINE["legitimate_ports"]
            baseline["threshold_settings"] = DEFAULT_BASELINE["threshold_settings"]

        return baseline

    def _extract_ports(self, pcap_path: str, protocol: str) -> list[int]:
        """Extract unique destination ports."""
        field = f"{protocol}.dstport"
        cmd = self.executor.build_command(
            pcap_path=pcap_path,
            fields=[field],
            display_filter=protocol
        )

        returncode, stdout, _ = self.executor.execute(cmd, timeout=300)

        ports = set()
        if returncode == 0:
            for line in stdout.strip().split("\n"):
                if line.strip():
                    try:
                        ports.add(int(line.strip()))
                    except ValueError:
                        pass

        return sorted(list(ports))

    def _extract_ips(self, pcap_path: str) -> list[str]:
        """Extract unique IP addresses."""
        results = self.executor.execute_and_parse_fields(
            pcap_path=pcap_path,
            fields=["ip.src", "ip.dst"],
            display_filter="ip",
            timeout=300
        )

        ips = set()
        for row in results:
            if row.get("ip.src"):
                ips.add(row["ip.src"])
            if row.get("ip.dst"):
                ips.add(row["ip.dst"])

        return sorted(list(ips))

    def _extract_protocols(self, pcap_path: str) -> list[str]:
        """Extract detected protocols."""
        stats = self.analyzer.get_protocol_hierarchy(pcap_path)
        return [s.protocol for s in stats]

    def _extract_dns_servers(self, pcap_path: str) -> list[str]:
        """Extract DNS server IPs (sources of DNS responses)."""
        results = self.executor.execute_and_parse_fields(
            pcap_path=pcap_path,
            fields=["ip.src"],
            display_filter="dns.flags.response == 1",
            timeout=120
        )

        servers = set()
        for row in results:
            if row.get("ip.src"):
                servers.add(row["ip.src"])

        return sorted(list(servers))

    def _extract_domains(self, pcap_path: str) -> list[str]:
        """Extract queried domain names."""
        results = self.executor.execute_and_parse_fields(
            pcap_path=pcap_path,
            fields=["dns.qry.name"],
            display_filter="dns.flags.response == 0",
            timeout=120
        )

        domains = Counter()
        for row in results:
            if row.get("dns.qry.name"):
                domains[row["dns.qry.name"]] += 1

        # Return most common domains
        return [d for d, _ in domains.most_common(1000)]

    def merge_baselines(self, baselines: list[dict]) -> dict[str, Any]:
        """Merge multiple baselines into one.

        Args:
            baselines: List of baseline dictionaries

        Returns:
            Merged baseline
        """
        merged = {
            "name": "merged",
            "created_at": datetime.now().isoformat(),
            "source_baselines": [],
            "observed_ports": {"tcp": set(), "udp": set()},
            "observed_ips": set(),
            "observed_protocols": set(),
            "observed_dns_servers": set(),
            "observed_domains": set()
        }

        for baseline in baselines:
            if baseline.get("name"):
                merged["source_baselines"].append(baseline["name"])

            # Merge ports
            for proto in ["tcp", "udp"]:
                ports = baseline.get("observed_ports", {}).get(proto, [])
                merged["observed_ports"][proto].update(ports)

            # Merge IPs
            merged["observed_ips"].update(baseline.get("observed_ips", []))

            # Merge protocols
            merged["observed_protocols"].update(baseline.get("observed_protocols", []))

            # Merge DNS servers
            merged["observed_dns_servers"].update(baseline.get("observed_dns_servers", []))

            # Merge domains
            merged["observed_domains"].update(baseline.get("observed_domains", []))

        # Convert sets to sorted lists
        merged["observed_ports"]["tcp"] = sorted(list(merged["observed_ports"]["tcp"]))
        merged["observed_ports"]["udp"] = sorted(list(merged["observed_ports"]["udp"]))
        merged["observed_ips"] = sorted(list(merged["observed_ips"]))
        merged["observed_protocols"] = sorted(list(merged["observed_protocols"]))
        merged["observed_dns_servers"] = sorted(list(merged["observed_dns_servers"]))
        merged["observed_domains"] = sorted(list(merged["observed_domains"]))[:1000]

        return merged
