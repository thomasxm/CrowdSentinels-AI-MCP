# src/wireshark/hunting/anomaly_detector.py
"""Protocol anomaly detection."""
import logging
import re
from datetime import datetime

from src.wireshark.baseline.defaults import (
    DEFAULT_BASELINE,
    get_threshold,
    is_internal_ip,
    is_legitimate_port,
    is_suspicious_port,
)
from src.wireshark.models import AnomalyFinding

logger = logging.getLogger(__name__)


class AnomalyDetector:
    """Detect protocol and traffic anomalies."""

    def __init__(self, baseline: dict | None = None):
        """Initialize detector with optional custom baseline."""
        self.baseline = baseline or DEFAULT_BASELINE

    def check_port_anomaly(
        self,
        port: int,
        protocol: str,
        occurrence_count: int,
        src_ip: str | None = None,
        dst_ip: str | None = None
    ) -> list[AnomalyFinding]:
        """Check for port-based anomalies.

        Args:
            port: Destination port
            protocol: Protocol (tcp/udp)
            occurrence_count: Number of connections
            src_ip: Source IP
            dst_ip: Destination IP

        Returns:
            List of anomaly findings
        """
        anomalies = []
        timestamp = datetime.now()

        # Check for known suspicious ports
        if is_suspicious_port(port, self.baseline):
            anomalies.append(AnomalyFinding(
                id=f"port-suspicious-{port}-{timestamp.timestamp()}",
                type="suspicious_port",
                severity="high",
                description=f"Connection to known suspicious port {port}/{protocol}",
                source_ip=src_ip or "unknown",
                dest_ip=dst_ip,
                port=port,
                protocol=protocol,
                evidence={"occurrences": occurrence_count},
                timestamp=timestamp,
                confidence=9
            ))

        # Check for non-standard ports with significant traffic
        elif not is_legitimate_port(port, protocol, self.baseline):
            threshold = get_threshold("unusual_port_threshold", self.baseline)
            if occurrence_count >= threshold:
                anomalies.append(AnomalyFinding(
                    id=f"port-unusual-{port}-{timestamp.timestamp()}",
                    type="unusual_port",
                    severity="medium",
                    description=f"Significant traffic on unusual port {port}/{protocol}",
                    source_ip=src_ip or "unknown",
                    dest_ip=dst_ip,
                    port=port,
                    protocol=protocol,
                    evidence={"occurrences": occurrence_count, "threshold": threshold},
                    timestamp=timestamp,
                    confidence=6
                ))

        return anomalies

    def check_dns_anomaly(
        self,
        query_name: str,
        query_type: str,
        response_code: str | None,
        src_ip: str = "unknown",
        response_size: int = 0
    ) -> list[AnomalyFinding]:
        """Check for DNS-based anomalies.

        Args:
            query_name: DNS query name
            query_type: Query type (A, AAAA, TXT, etc.)
            response_code: Response code (NOERROR, NXDOMAIN, etc.)
            src_ip: Source IP
            response_size: Size of DNS response

        Returns:
            List of anomaly findings
        """
        anomalies = []
        timestamp = datetime.now()

        max_length = get_threshold("dns_query_length_max", self.baseline)
        max_txt_size = get_threshold("dns_txt_size_max", self.baseline)

        # Check for long query names (potential tunneling)
        if len(query_name) > max_length:
            anomalies.append(AnomalyFinding(
                id=f"dns-long-query-{timestamp.timestamp()}",
                type="dns_tunnel_suspect",
                severity="high",
                description=f"Unusually long DNS query ({len(query_name)} chars): {query_name[:50]}...",
                source_ip=src_ip,
                protocol="dns",
                evidence={
                    "query_name": query_name,
                    "length": len(query_name),
                    "threshold": max_length
                },
                timestamp=timestamp,
                confidence=7
            ))

        # Check for high-entropy subdomains (potential DGA or tunneling)
        if self._is_high_entropy(query_name):
            anomalies.append(AnomalyFinding(
                id=f"dns-entropy-{timestamp.timestamp()}",
                type="dns_high_entropy",
                severity="medium",
                description=f"High-entropy DNS query (potential DGA): {query_name}",
                source_ip=src_ip,
                protocol="dns",
                evidence={"query_name": query_name},
                timestamp=timestamp,
                confidence=6
            ))

        # Check for large TXT responses (potential exfil)
        if query_type == "TXT" and response_size > max_txt_size:
            anomalies.append(AnomalyFinding(
                id=f"dns-large-txt-{timestamp.timestamp()}",
                type="dns_exfil_suspect",
                severity="high",
                description=f"Large DNS TXT response ({response_size} bytes)",
                source_ip=src_ip,
                protocol="dns",
                evidence={
                    "query_name": query_name,
                    "response_size": response_size,
                    "threshold": max_txt_size
                },
                timestamp=timestamp,
                confidence=7
            ))

        return anomalies

    def check_tls_anomaly(
        self,
        has_sni: bool,
        server_ip: str,
        ja3_hash: str | None = None,
        cert_cn: str | None = None,
        src_ip: str = "unknown"
    ) -> list[AnomalyFinding]:
        """Check for TLS-based anomalies.

        Args:
            has_sni: Whether SNI extension is present
            server_ip: Server IP address
            ja3_hash: JA3 fingerprint hash
            cert_cn: Certificate Common Name
            src_ip: Source IP

        Returns:
            List of anomaly findings
        """
        anomalies = []
        timestamp = datetime.now()

        # TLS without SNI is suspicious (common in malware)
        if not has_sni:
            anomalies.append(AnomalyFinding(
                id=f"tls-no-sni-{timestamp.timestamp()}",
                type="tls_no_sni",
                severity="medium",
                description=f"TLS connection without SNI to {server_ip}",
                source_ip=src_ip,
                dest_ip=server_ip,
                protocol="tls",
                evidence={
                    "has_sni": False,
                    "ja3": ja3_hash,
                    "cert_cn": cert_cn
                },
                timestamp=timestamp,
                confidence=6
            ))

        # Self-signed or suspicious cert (if CN doesn't match IP pattern)
        if cert_cn and self._is_suspicious_cert(cert_cn, server_ip):
            anomalies.append(AnomalyFinding(
                id=f"tls-suspicious-cert-{timestamp.timestamp()}",
                type="tls_suspicious_cert",
                severity="medium",
                description=f"Suspicious TLS certificate: {cert_cn}",
                source_ip=src_ip,
                dest_ip=server_ip,
                protocol="tls",
                evidence={"cert_cn": cert_cn},
                timestamp=timestamp,
                confidence=5
            ))

        return anomalies

    def check_traffic_volume_anomaly(
        self,
        src_ip: str,
        dst_ip: str,
        bytes_sent: int,
        bytes_received: int,
        duration_seconds: float
    ) -> list[AnomalyFinding]:
        """Check for traffic volume anomalies.

        Args:
            src_ip: Source IP
            dst_ip: Destination IP
            bytes_sent: Bytes sent from source
            bytes_received: Bytes received at source
            duration_seconds: Session duration

        Returns:
            List of anomaly findings
        """
        anomalies = []
        timestamp = datetime.now()

        large_upload = get_threshold("large_upload_bytes", self.baseline)

        # Large upload to external IP
        if bytes_sent > large_upload and not is_internal_ip(dst_ip):
            anomalies.append(AnomalyFinding(
                id=f"traffic-large-upload-{timestamp.timestamp()}",
                type="large_upload",
                severity="high",
                description=f"Large data upload ({bytes_sent / 1048576:.1f} MB) to external IP {dst_ip}",
                source_ip=src_ip,
                dest_ip=dst_ip,
                evidence={
                    "bytes_sent": bytes_sent,
                    "bytes_received": bytes_received,
                    "duration": duration_seconds,
                    "threshold": large_upload
                },
                timestamp=timestamp,
                confidence=7
            ))

        # Highly asymmetric traffic (potential exfil)
        if bytes_sent > 0 and bytes_received > 0:
            ratio = bytes_sent / bytes_received
            if ratio > 10 and bytes_sent > 1048576:  # >10:1 ratio and >1MB
                anomalies.append(AnomalyFinding(
                    id=f"traffic-asymmetric-{timestamp.timestamp()}",
                    type="asymmetric_traffic",
                    severity="medium",
                    description=f"Highly asymmetric traffic (ratio {ratio:.1f}:1) to {dst_ip}",
                    source_ip=src_ip,
                    dest_ip=dst_ip,
                    evidence={
                        "bytes_sent": bytes_sent,
                        "bytes_received": bytes_received,
                        "ratio": ratio
                    },
                    timestamp=timestamp,
                    confidence=6
                ))

        return anomalies

    def _is_high_entropy(self, domain: str) -> bool:
        """Check if domain has high entropy (potential DGA)."""
        # Extract subdomain part
        parts = domain.split(".")
        if len(parts) < 2:
            return False

        subdomain = parts[0]
        if len(subdomain) < 10:
            return False

        # Check for random-looking patterns
        # High ratio of consonants to vowels
        vowels = sum(1 for c in subdomain.lower() if c in "aeiou")
        consonants = sum(1 for c in subdomain.lower() if c.isalpha() and c not in "aeiou")

        if consonants > 0 and vowels > 0:
            ratio = consonants / vowels
            if ratio > 4:  # Very consonant-heavy
                return True

        # Check for numeric patterns
        digits = sum(1 for c in subdomain if c.isdigit())
        if digits > len(subdomain) * 0.3:  # >30% digits
            return True

        return False

    def _is_suspicious_cert(self, cert_cn: str, server_ip: str) -> bool:
        """Check if certificate CN is suspicious."""
        # IP address as CN
        if re.match(r"\d+\.\d+\.\d+\.\d+", cert_cn):
            return True

        # localhost or test certs
        suspicious_patterns = [
            "localhost", "test", "self-signed", "example",
            "changeme", "default", "*.local"
        ]

        cn_lower = cert_cn.lower()
        return any(p in cn_lower for p in suspicious_patterns)
