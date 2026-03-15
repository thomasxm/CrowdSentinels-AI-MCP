# src/wireshark/extraction/object_extractor.py
"""HTTP/SMB/FTP object extraction from PCAP files."""
import hashlib
import logging
import os
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Any

from src.wireshark.models import ExtractedObject

logger = logging.getLogger(__name__)

# Supported protocols for object extraction
SUPPORTED_PROTOCOLS = {
    "http": "http",
    "smb": "smb",
    "tftp": "tftp",
    "imf": "imf",  # Internet Message Format (email)
    "dicom": "dicom",
}


class ObjectExtractor:
    """Extract objects from network traffic captures."""

    def __init__(
        self,
        store_files: bool = False,
        storage_path: Path | None = None
    ):
        """Initialize object extractor.

        Args:
            store_files: Whether to store extracted files (default: metadata only)
            storage_path: Path for storing extracted files (if enabled)
        """
        self.store_files = store_files
        self.storage_path = storage_path or Path.home() / ".crowdsentinel" / "wireshark" / "artifact_storage"
        self._tshark_path = "tshark"

    @property
    def supported_protocols(self) -> list[str]:
        """Get list of supported protocols."""
        return list(SUPPORTED_PROTOCOLS.keys())

    def list_objects(
        self,
        pcap_path: str,
        protocol: str = "http"
    ) -> list[dict]:
        """List objects in PCAP without extracting.

        Args:
            pcap_path: Path to PCAP file
            protocol: Protocol to extract (http, smb, etc.)

        Returns:
            List of object metadata dictionaries
        """
        if protocol not in SUPPORTED_PROTOCOLS:
            logger.warning(f"Unsupported protocol: {protocol}")
            return []

        # Use tshark to list objects
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                cmd = [
                    self._tshark_path,
                    "-r", pcap_path,
                    "--export-objects", f"{SUPPORTED_PROTOCOLS[protocol]},{tmpdir}",
                    "-q"  # Quiet mode
                ]

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300
                )

                # List extracted files
                objects = []
                for filename in os.listdir(tmpdir):
                    filepath = os.path.join(tmpdir, filename)
                    if os.path.isfile(filepath):
                        stat = os.stat(filepath)
                        objects.append({
                            "filename": filename,
                            "size": stat.st_size,
                            "protocol": protocol
                        })

                return objects

            except subprocess.TimeoutExpired:
                logger.error("Timeout listing objects")
                return []
            except Exception as e:
                logger.error(f"Error listing objects: {e}")
                return []

    def extract_objects(
        self,
        pcap_path: str,
        output_dir: str,
        protocol: str = "http",
        compute_hash: bool = True
    ) -> dict[str, Any]:
        """Extract objects from PCAP to directory.

        Args:
            pcap_path: Path to PCAP file
            output_dir: Directory to extract to
            protocol: Protocol to extract
            compute_hash: Whether to compute SHA256 hashes

        Returns:
            Extraction result dictionary
        """
        if protocol not in SUPPORTED_PROTOCOLS:
            return {
                "success": False,
                "error": f"Unsupported protocol: {protocol}",
                "extracted_count": 0,
                "output_dir": output_dir
            }

        try:
            # Ensure output directory exists
            os.makedirs(output_dir, exist_ok=True)

            cmd = [
                self._tshark_path,
                "-r", pcap_path,
                "--export-objects", f"{SUPPORTED_PROTOCOLS[protocol]},{output_dir}",
                "-q"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )

            # Get extracted objects
            extracted = []
            for filename in os.listdir(output_dir):
                filepath = os.path.join(output_dir, filename)
                if os.path.isfile(filepath):
                    obj_info = {
                        "filename": filename,
                        "size": os.path.getsize(filepath),
                        "path": filepath,
                        "protocol": protocol
                    }

                    if compute_hash:
                        obj_info["sha256"] = self._compute_sha256(filepath)

                    extracted.append(obj_info)

            return {
                "success": True,
                "extracted_count": len(extracted),
                "output_dir": output_dir,
                "objects": extracted
            }

        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Timeout during extraction",
                "extracted_count": 0,
                "output_dir": output_dir
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "extracted_count": 0,
                "output_dir": output_dir
            }

    def build_metadata(
        self,
        object_data: dict,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        timestamp: datetime | None = None
    ) -> dict[str, Any]:
        """Build metadata dictionary for an extracted object.

        Args:
            object_data: Raw object data from tshark
            src_ip: Source IP address
            dst_ip: Destination IP address
            protocol: Protocol type
            timestamp: Extraction timestamp

        Returns:
            Metadata dictionary
        """
        return {
            "filename": object_data.get("filename", "unknown"),
            "protocol": protocol,
            "size_bytes": object_data.get("size", 0),
            "content_type": object_data.get("content_type"),
            "hostname": object_data.get("hostname"),
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "packet_number": object_data.get("packet"),
            "timestamp": timestamp or datetime.now()
        }

    def create_extracted_object(
        self,
        metadata: dict,
        pcap_path: str,
        local_path: str | None = None
    ) -> ExtractedObject:
        """Create ExtractedObject model from metadata.

        Args:
            metadata: Metadata dictionary
            pcap_path: Source PCAP path
            local_path: Local storage path (if stored)

        Returns:
            ExtractedObject instance
        """
        obj_id = f"obj-{metadata.get('sha256', 'unknown')[:16]}-{datetime.now().timestamp()}"

        return ExtractedObject(
            id=obj_id,
            source_pcap=pcap_path,
            protocol=metadata.get("protocol", "unknown"),
            filename=metadata.get("filename", "unknown"),
            sha256=metadata.get("sha256", ""),
            size_bytes=metadata.get("size_bytes", 0),
            mime_type=metadata.get("mime_type") or metadata.get("content_type"),
            source_ip=metadata.get("src_ip", "unknown"),
            dest_ip=metadata.get("dst_ip", "unknown"),
            timestamp=metadata.get("timestamp", datetime.now()),
            stored_locally=local_path is not None,
            local_path=local_path
        )

    def filter_by_extension(
        self,
        objects: list[dict],
        extensions: list[str]
    ) -> list[dict]:
        """Filter objects by file extension.

        Args:
            objects: List of object dictionaries
            extensions: List of extensions to match (e.g., [".exe", ".dll"])

        Returns:
            Filtered list
        """
        # Normalize extensions
        normalized = [ext.lower() if ext.startswith(".") else f".{ext.lower()}" for ext in extensions]

        filtered = []
        for obj in objects:
            filename = obj.get("filename", "").lower()
            for ext in normalized:
                if filename.endswith(ext):
                    filtered.append(obj)
                    break

        return filtered

    def filter_by_size(
        self,
        objects: list[dict],
        min_size: int = 0,
        max_size: int | None = None
    ) -> list[dict]:
        """Filter objects by size.

        Args:
            objects: List of object dictionaries
            min_size: Minimum size in bytes
            max_size: Maximum size in bytes (None for no limit)

        Returns:
            Filtered list
        """
        filtered = []
        for obj in objects:
            size = obj.get("size", 0)
            if size >= min_size:
                if max_size is None or size <= max_size:
                    filtered.append(obj)

        return filtered

    def filter_suspicious(
        self,
        objects: list[dict]
    ) -> list[dict]:
        """Filter for potentially suspicious objects.

        Looks for: executables, scripts, archives, documents with macros

        Args:
            objects: List of object dictionaries

        Returns:
            Suspicious objects
        """
        suspicious_extensions = [
            ".exe", ".dll", ".scr", ".pif", ".bat", ".cmd", ".ps1",
            ".vbs", ".js", ".jse", ".wsf", ".wsh",
            ".zip", ".rar", ".7z", ".tar", ".gz",
            ".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm",
            ".hta", ".msi", ".jar", ".class"
        ]

        return self.filter_by_extension(objects, suspicious_extensions)

    def extract_from_pcap(
        self,
        pcap_path: str,
        protocols: list[str] | None = None,
        store_files: bool | None = None
    ) -> dict[str, Any]:
        """Extract all objects from PCAP file.

        Args:
            pcap_path: Path to PCAP file
            protocols: Protocols to extract (default: all supported)
            store_files: Whether to store files (overrides instance setting)

        Returns:
            Extraction results
        """
        if protocols is None:
            protocols = ["http", "smb"]

        should_store = store_files if store_files is not None else self.store_files

        all_objects = []
        results = {
            "pcap_path": pcap_path,
            "protocols_checked": protocols,
            "total_objects": 0,
            "objects_by_protocol": {}
        }

        for protocol in protocols:
            if protocol not in SUPPORTED_PROTOCOLS:
                continue

            if should_store:
                # Extract to storage path
                output_dir = self.storage_path / f"extraction_{datetime.now().strftime('%Y%m%d_%H%M%S')}" / protocol
                extraction = self.extract_objects(
                    pcap_path=pcap_path,
                    output_dir=str(output_dir),
                    protocol=protocol,
                    compute_hash=True
                )
            else:
                # Extract to temp dir (will be cleaned up)
                with tempfile.TemporaryDirectory() as tmpdir:
                    extraction = self.extract_objects(
                        pcap_path=pcap_path,
                        output_dir=tmpdir,
                        protocol=protocol,
                        compute_hash=True
                    )

            results["objects_by_protocol"][protocol] = extraction.get("objects", [])
            all_objects.extend(extraction.get("objects", []))

        results["total_objects"] = len(all_objects)
        results["objects"] = all_objects

        return results

    def _compute_sha256(self, filepath: str) -> str:
        """Compute SHA256 hash of file.

        Args:
            filepath: Path to file

        Returns:
            SHA256 hash string
        """
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    def get_extraction_summary(
        self,
        results: dict[str, Any]
    ) -> str:
        """Generate human-readable extraction summary.

        Args:
            results: Results from extract_from_pcap

        Returns:
            Summary string
        """
        lines = []
        lines.append("=" * 60)
        lines.append(" OBJECT EXTRACTION SUMMARY")
        lines.append("=" * 60)
        lines.append("")
        lines.append(f"PCAP: {results.get('pcap_path', 'unknown')}")
        lines.append(f"Total Objects: {results.get('total_objects', 0)}")
        lines.append("")

        for protocol, objects in results.get("objects_by_protocol", {}).items():
            lines.append(f"  {protocol.upper()}: {len(objects)} objects")
            for obj in objects[:5]:  # Show first 5
                lines.append(f"    - {obj.get('filename', 'unknown')} ({obj.get('size', 0)} bytes)")
            if len(objects) > 5:
                lines.append(f"    ... and {len(objects) - 5} more")

        lines.append("")
        lines.append("=" * 60)

        return "\n".join(lines)
