# src/wireshark/baseline/defaults.py
"""Prebuilt baseline defaults for network analysis."""
import ipaddress
from typing import Dict, List, Any


DEFAULT_BASELINE: Dict[str, Any] = {
    "legitimate_ports": {
        "tcp": [
            20, 21,      # FTP
            22,          # SSH
            23,          # Telnet (legacy)
            25,          # SMTP
            53,          # DNS
            80,          # HTTP
            110,         # POP3
            143,         # IMAP
            443,         # HTTPS
            445,         # SMB
            465,         # SMTPS
            587,         # SMTP submission
            636,         # LDAPS
            993,         # IMAPS
            995,         # POP3S
            1433,        # MSSQL
            1521,        # Oracle
            3306,        # MySQL
            3389,        # RDP
            5432,        # PostgreSQL
            5985, 5986,  # WinRM
            8080, 8443,  # HTTP alt
        ],
        "udp": [
            53,          # DNS
            67, 68,      # DHCP
            69,          # TFTP
            123,         # NTP
            137, 138,    # NetBIOS
            161, 162,    # SNMP
            500,         # IKE
            514,         # Syslog
            1194,        # OpenVPN
            4500,        # NAT-T
        ]
    },
    "legitimate_protocols": [
        "http", "https", "dns", "smtp", "imap", "pop", "ssh", "rdp",
        "smb", "smb2", "ntp", "ldap", "kerberos", "dhcp", "ftp",
        "tftp", "snmp", "syslog", "nfs", "mysql", "postgresql"
    ],
    "internal_ranges": [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",      # Loopback
        "169.254.0.0/16",   # Link-local
    ],
    "multicast_ranges": [
        "224.0.0.0/4",      # Multicast
        "ff00::/8",         # IPv6 multicast
    ],
    "dns_servers": [],  # User populates per environment
    "known_domains": [],  # User populates per environment
    "threshold_settings": {
        # DNS anomaly detection
        "dns_query_length_max": 50,       # Chars - longer may indicate tunneling
        "dns_txt_size_max": 200,          # Bytes - larger may indicate exfil
        "dns_nxdomain_threshold": 10,     # Per minute - excessive may indicate DGA

        # Beaconing detection
        "beacon_interval_tolerance": 0.90, # 90% jitter — real C2 beacons use sleep jitter to evade detection
        "min_beacon_count": 5,             # Minimum intervals to flag
        "beacon_min_interval": 10,         # Seconds - ignore faster
        "beacon_max_interval": 3600,       # Seconds - ignore slower

        # Authentication anomalies
        "failed_login_threshold": 5,       # Per 15 min window
        "login_spray_threshold": 3,        # Different users per source

        # Traffic anomalies
        "unusual_port_threshold": 10,      # Connections to flag
        "large_dns_response_bytes": 512,   # Bytes
        "large_upload_bytes": 10485760,    # 10MB

        # Session anomalies
        "long_session_minutes": 60,        # Minutes
        "idle_session_minutes": 30,        # Minutes with no data
    },
    "suspicious_ports": [
        4444,    # Metasploit default
        5555,    # Android debug
        6666, 6667,  # IRC (common C2)
        8888,    # Common backdoor
        9001, 9030,  # Tor
        31337,   # Elite/Back Orifice
    ],
    "suspicious_user_agents": [
        "curl", "wget", "python-requests", "powershell",
        "Mozilla/4.0", "Mozilla/5.0 (compatible;",  # Old/suspicious
    ]
}


# Pre-parsed internal networks for fast lookup
_INTERNAL_NETWORKS = [
    ipaddress.ip_network(cidr) for cidr in DEFAULT_BASELINE["internal_ranges"]
]


def is_internal_ip(ip: str) -> bool:
    """Check if IP address is internal/private.

    Args:
        ip: IP address string

    Returns:
        True if IP is internal/private
    """
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in network for network in _INTERNAL_NETWORKS)
    except ValueError:
        return False


def is_legitimate_port(port: int, protocol: str, baseline: Dict = None) -> bool:
    """Check if port is in legitimate ports list.

    Args:
        port: Port number
        protocol: Protocol (tcp/udp)
        baseline: Baseline dict (uses default if None)

    Returns:
        True if port is legitimate
    """
    if baseline is None:
        baseline = DEFAULT_BASELINE

    protocol = protocol.lower()
    legitimate = baseline.get("legitimate_ports", {}).get(protocol, [])
    return port in legitimate


def is_suspicious_port(port: int, baseline: Dict = None) -> bool:
    """Check if port is in suspicious ports list.

    Args:
        port: Port number
        baseline: Baseline dict (uses default if None)

    Returns:
        True if port is suspicious
    """
    if baseline is None:
        baseline = DEFAULT_BASELINE

    return port in baseline.get("suspicious_ports", [])


def get_threshold(name: str, baseline: Dict = None) -> Any:
    """Get a threshold value from baseline.

    Args:
        name: Threshold name
        baseline: Baseline dict (uses default if None)

    Returns:
        Threshold value or None
    """
    if baseline is None:
        baseline = DEFAULT_BASELINE

    return baseline.get("threshold_settings", {}).get(name)
