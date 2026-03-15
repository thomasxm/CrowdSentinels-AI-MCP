# src/wireshark/hunting/ioc_hunter.py
"""IoC-driven traffic filtering and hunting."""
import logging
import re
from datetime import datetime
from typing import Any

from src.wireshark.models import NetworkIoC, PyramidLevel

logger = logging.getLogger(__name__)


class IoCHunter:
    """Hunt for Indicators of Compromise in network traffic."""

    def __init__(self):
        """Initialize IoC hunter."""
        self._compiled_patterns: dict[str, re.Pattern] = {}

    def hunt_ips(
        self,
        ip_iocs: list[str],
        connections: list[dict],
        check_both_directions: bool = True
    ) -> list[dict]:
        """Hunt for IP addresses in connection data.

        Args:
            ip_iocs: List of IP addresses to hunt for
            connections: List of connection dicts with src_ip, dst_ip
            check_both_directions: Check both source and destination

        Returns:
            List of matching connections
        """
        if not ip_iocs:
            return []

        ioc_set = set(ip_iocs)
        matches = []

        for conn in connections:
            src_ip = conn.get("src_ip", "")
            dst_ip = conn.get("dst_ip", "")

            matched = False
            matched_ioc = None

            if dst_ip in ioc_set:
                matched = True
                matched_ioc = dst_ip

            if check_both_directions and src_ip in ioc_set:
                matched = True
                matched_ioc = src_ip

            if matched:
                match_result = conn.copy()
                match_result["matched_ioc"] = matched_ioc
                match_result["match_type"] = "ip"
                matches.append(match_result)

        return matches

    def hunt_domains(
        self,
        domain_iocs: list[str],
        dns_queries: list[dict],
        include_subdomains: bool = True
    ) -> list[dict]:
        """Hunt for domains in DNS query data.

        Args:
            domain_iocs: List of domains to hunt for
            dns_queries: List of DNS query dicts with query_name
            include_subdomains: Also match subdomains of IoC domains

        Returns:
            List of matching queries
        """
        if not domain_iocs:
            return []

        matches = []

        for query in dns_queries:
            query_name = query.get("query_name", "").lower()

            for domain in domain_iocs:
                domain_lower = domain.lower()
                matched = False

                if query_name == domain_lower or include_subdomains and query_name.endswith("." + domain_lower):
                    matched = True

                if matched:
                    match_result = query.copy()
                    match_result["matched_ioc"] = domain
                    match_result["match_type"] = "domain"
                    matches.append(match_result)
                    break  # Don't double-match

        return matches

    def hunt_hashes(
        self,
        hash_iocs: list[str],
        file_transfers: list[dict]
    ) -> list[dict]:
        """Hunt for file hashes in transfer data.

        Args:
            hash_iocs: List of MD5/SHA1/SHA256 hashes
            file_transfers: List of file transfer dicts with hash field

        Returns:
            List of matching transfers
        """
        if not hash_iocs:
            return []

        # Normalize hashes to lowercase
        ioc_set = set(h.lower() for h in hash_iocs)
        matches = []

        for transfer in file_transfers:
            # Check various hash fields
            for hash_field in ["md5", "sha1", "sha256", "hash"]:
                file_hash = transfer.get(hash_field, "").lower()
                if file_hash and file_hash in ioc_set:
                    match_result = transfer.copy()
                    match_result["matched_ioc"] = file_hash
                    match_result["match_type"] = "hash"
                    matches.append(match_result)
                    break

        return matches

    def hunt_user_agents(
        self,
        ua_patterns: list[str],
        http_requests: list[dict]
    ) -> list[dict]:
        """Hunt for suspicious user agents in HTTP traffic.

        Args:
            ua_patterns: List of user agent strings or regex patterns
            http_requests: List of HTTP request dicts with user_agent field

        Returns:
            List of matching requests
        """
        if not ua_patterns:
            return []

        matches = []

        # Compile patterns
        compiled = []
        for pattern in ua_patterns:
            try:
                compiled.append((pattern, re.compile(pattern, re.IGNORECASE)))
            except re.error:
                # Treat as literal string
                compiled.append((pattern, None))

        for request in http_requests:
            user_agent = request.get("user_agent", "")

            for pattern, regex in compiled:
                matched = False

                if regex:
                    if regex.search(user_agent):
                        matched = True
                else:
                    if pattern.lower() in user_agent.lower():
                        matched = True

                if matched:
                    match_result = request.copy()
                    match_result["matched_ioc"] = pattern
                    match_result["match_type"] = "user_agent"
                    matches.append(match_result)
                    break

        return matches

    def hunt_iocs_in_pcap(
        self,
        pcap_path: str,
        ip_iocs: list[str] | None = None,
        domain_iocs: list[str] | None = None,
        hash_iocs: list[str] | None = None,
        executor=None
    ) -> dict[str, Any]:
        """Hunt for all IoC types in a PCAP file.

        Args:
            pcap_path: Path to PCAP file
            ip_iocs: List of IP addresses to hunt
            domain_iocs: List of domains to hunt
            hash_iocs: List of file hashes to hunt
            executor: Optional TSharkExecutor instance

        Returns:
            Dictionary with matches and summary
        """
        from src.wireshark.core.tshark_executor import TSharkExecutor

        if executor is None:
            executor = TSharkExecutor()

        all_matches = []
        summary = {
            "ip_matches": 0,
            "domain_matches": 0,
            "hash_matches": 0,
            "total_matches": 0,
            "unique_iocs_found": set()
        }

        # Hunt IPs
        if ip_iocs:
            connections = self._extract_connections(pcap_path, executor)
            ip_matches = self.hunt_ips(ip_iocs, connections)
            all_matches.extend(ip_matches)
            summary["ip_matches"] = len(ip_matches)
            for m in ip_matches:
                summary["unique_iocs_found"].add(m.get("matched_ioc"))

        # Hunt domains
        if domain_iocs:
            dns_queries = self._extract_dns_queries(pcap_path, executor)
            domain_matches = self.hunt_domains(domain_iocs, dns_queries)
            all_matches.extend(domain_matches)
            summary["domain_matches"] = len(domain_matches)
            for m in domain_matches:
                summary["unique_iocs_found"].add(m.get("matched_ioc"))

        # Convert set to list for JSON serialization
        summary["unique_iocs_found"] = list(summary["unique_iocs_found"])
        summary["total_matches"] = len(all_matches)

        return {
            "matches": all_matches,
            "summary": summary
        }

    def _extract_connections(self, pcap_path: str, executor) -> list[dict]:
        """Extract connection data from PCAP."""
        results = executor.execute_and_parse_fields(
            pcap_path=pcap_path,
            fields=["ip.src", "ip.dst", "tcp.dstport", "udp.dstport", "frame.time_epoch"],
            display_filter="ip",
            timeout=300
        )

        connections = []
        for row in results:
            if row.get("ip.src") and row.get("ip.dst"):
                connections.append({
                    "src_ip": row["ip.src"],
                    "dst_ip": row["ip.dst"],
                    "dst_port": row.get("tcp.dstport") or row.get("udp.dstport"),
                    "timestamp": row.get("frame.time_epoch"),
                    "protocol": "tcp" if row.get("tcp.dstport") else "udp"
                })

        return connections

    def _extract_dns_queries(self, pcap_path: str, executor) -> list[dict]:
        """Extract DNS query data from PCAP."""
        results = executor.execute_and_parse_fields(
            pcap_path=pcap_path,
            fields=["dns.qry.name", "ip.src", "frame.time_epoch"],
            display_filter="dns.flags.response == 0",
            timeout=120
        )

        queries = []
        for row in results:
            if row.get("dns.qry.name"):
                queries.append({
                    "query_name": row["dns.qry.name"],
                    "src_ip": row.get("ip.src"),
                    "timestamp": row.get("frame.time_epoch")
                })

        return queries

    def create_iocs_from_matches(
        self,
        matches: list[dict],
        source_tool: str = "wireshark"
    ) -> list[NetworkIoC]:
        """Create NetworkIoC objects from hunt matches.

        Args:
            matches: List of match dictionaries
            source_tool: Name of source tool

        Returns:
            List of NetworkIoC objects
        """
        iocs = []
        seen = set()
        now = datetime.now()

        for match in matches:
            ioc_value = match.get("matched_ioc")
            match_type = match.get("match_type")

            if not ioc_value or ioc_value in seen:
                continue

            seen.add(ioc_value)

            # Determine pyramid level based on type
            if match_type == "ip":
                pyramid_level = PyramidLevel.IP
            elif match_type == "domain":
                pyramid_level = PyramidLevel.DOMAIN
            elif match_type == "hash":
                pyramid_level = PyramidLevel.HASH
            else:
                pyramid_level = PyramidLevel.ARTIFACTS

            ioc = NetworkIoC(
                id=f"hunt-{match_type}-{hash(ioc_value)}",
                type=match_type,
                value=ioc_value,
                pyramid_level=pyramid_level,
                confidence=7,
                first_seen=now,
                last_seen=now,
                occurrence_count=1,
                source_tool=source_tool,
                context={"hunt_match": True}
            )
            iocs.append(ioc)

        return iocs
