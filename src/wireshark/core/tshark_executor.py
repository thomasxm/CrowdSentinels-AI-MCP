# src/wireshark/core/tshark_executor.py
"""TShark command executor and builder."""
import logging
import shutil
import subprocess

logger = logging.getLogger(__name__)


def escape_filter_value(value: str) -> str:
    """Escape a value for use in tshark display filters."""
    # Escape backslashes first, then quotes
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return escaped


def build_ip_filter(ips: list[str], field: str = "ip.addr") -> str:
    """Build a filter for multiple IP addresses."""
    if not ips:
        return ""
    conditions = [f'{field} == {ip}' for ip in ips]
    return " || ".join(conditions)


def build_port_filter(ports: list[int], protocol: str = "tcp") -> str:
    """Build a filter for multiple ports."""
    if not ports:
        return ""
    conditions = [f'{protocol}.port == {port}' for port in ports]
    return " || ".join(conditions)


def build_domain_filter(domains: list[str]) -> str:
    """Build a filter for DNS domain queries."""
    if not domains:
        return ""
    conditions = []
    for domain in domains:
        escaped = escape_filter_value(domain)
        conditions.append(f'dns.qry.name contains "{escaped}"')
    return " || ".join(conditions)


class TSharkExecutor:
    """Execute TShark commands safely."""

    def __init__(self, tshark_path: str | None = None):
        """Initialize executor with tshark path."""
        self.tshark_path = tshark_path or shutil.which("tshark") or "/usr/bin/tshark"
        self._version: str | None = None

    def is_available(self) -> bool:
        """Check if tshark is available."""
        try:
            result = subprocess.run(
                [self.tshark_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.returncode == 0
        except (subprocess.SubprocessError, FileNotFoundError):
            return False

    def get_version(self) -> str | None:
        """Get tshark version string."""
        if self._version:
            return self._version
        try:
            result = subprocess.run(
                [self.tshark_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                self._version = result.stdout.split("\n")[0]
                return self._version
        except subprocess.SubprocessError:
            pass
        return None

    def build_command(
        self,
        pcap_path: str,
        display_filter: str | None = None,
        fields: list[str] | None = None,
        output_format: str = "fields",
        limit: int | None = None,
        no_resolve: bool = True,
        additional_args: list[str] | None = None
    ) -> list[str]:
        """Build a tshark command for reading pcap files.

        Args:
            pcap_path: Path to pcap file
            display_filter: Wireshark display filter (-Y)
            fields: List of fields to extract (-e)
            output_format: Output format (fields, json, pdml)
            limit: Max packets to process (-c)
            no_resolve: Disable name resolution (-n)
            additional_args: Additional command arguments

        Returns:
            Command as list of strings
        """
        cmd = [self.tshark_path, "-r", pcap_path]

        if no_resolve:
            cmd.append("-n")

        if display_filter:
            cmd.extend(["-Y", display_filter])

        if limit:
            cmd.extend(["-c", str(limit)])

        if output_format == "fields" and fields:
            cmd.extend(["-T", "fields"])
            for field in fields:
                cmd.extend(["-e", field])
            # Add tab separator for parsing
            cmd.extend(["-E", "separator=\t"])
        elif output_format == "json":
            cmd.extend(["-T", "json"])
        elif output_format == "pdml":
            cmd.extend(["-T", "pdml"])

        if additional_args:
            cmd.extend(additional_args)

        return cmd

    def build_stats_command(
        self,
        pcap_path: str,
        stat_type: str,
        display_filter: str | None = None
    ) -> list[str]:
        """Build a tshark command for statistics.

        Args:
            pcap_path: Path to pcap file
            stat_type: Statistics type (io,phs | conv,tcp | endpoints,ip | etc.)
            display_filter: Optional display filter

        Returns:
            Command as list of strings
        """
        cmd = [self.tshark_path, "-r", pcap_path, "-n", "-q", "-z", stat_type]

        if display_filter:
            cmd.extend(["-Y", display_filter])

        return cmd

    def build_follow_stream_command(
        self,
        pcap_path: str,
        stream_type: str,
        stream_index: int,
        output_type: str = "ascii"
    ) -> list[str]:
        """Build command to follow a TCP/UDP stream.

        Args:
            pcap_path: Path to pcap file
            stream_type: tcp or udp
            stream_index: Stream index number
            output_type: ascii, hex, raw

        Returns:
            Command as list of strings
        """
        return [
            self.tshark_path, "-r", pcap_path, "-q",
            "-z", f"follow,{stream_type},{output_type},{stream_index}"
        ]

    def build_export_objects_command(
        self,
        pcap_path: str,
        protocol: str,
        output_dir: str
    ) -> list[str]:
        """Build command to export objects (HTTP, SMB, etc.).

        Args:
            pcap_path: Path to pcap file
            protocol: Protocol (http, smb, imf, tftp, dicom)
            output_dir: Directory to export objects to

        Returns:
            Command as list of strings
        """
        return [
            self.tshark_path, "-r", pcap_path,
            "--export-objects", f"{protocol},{output_dir}"
        ]

    def execute(
        self,
        cmd: list[str],
        timeout: int = 300
    ) -> tuple[int, str, str]:
        """Execute a tshark command.

        Args:
            cmd: Command as list of strings
            timeout: Timeout in seconds

        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        logger.debug(f"Executing: {' '.join(cmd)}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out after {timeout}s: {' '.join(cmd)}")
            return -1, "", f"Command timed out after {timeout} seconds"
        except Exception as e:
            logger.error(f"Command failed: {e}")
            return -1, "", str(e)

    def execute_and_parse_fields(
        self,
        pcap_path: str,
        fields: list[str],
        display_filter: str | None = None,
        limit: int | None = None,
        timeout: int = 300
    ) -> list[dict[str, str]]:
        """Execute tshark and parse field output.

        Returns:
            List of dicts mapping field names to values
        """
        cmd = self.build_command(
            pcap_path=pcap_path,
            display_filter=display_filter,
            fields=fields,
            output_format="fields",
            limit=limit
        )

        returncode, stdout, stderr = self.execute(cmd, timeout)

        if returncode != 0:
            logger.error(f"TShark error: {stderr}")
            return []

        results = []
        for line in stdout.strip().split("\n"):
            if not line:
                continue
            values = line.split("\t")
            if len(values) == len(fields):
                results.append(dict(zip(fields, values)))
            elif len(values) < len(fields):
                # Pad with empty strings
                padded = values + [""] * (len(fields) - len(values))
                results.append(dict(zip(fields, padded)))

        return results
