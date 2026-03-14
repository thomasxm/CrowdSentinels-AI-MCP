# src/wireshark/extraction/hasher.py
"""File hashing utilities with metadata for forensic analysis."""
import hashlib
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)

# File category mappings by extension
FILE_CATEGORIES = {
    "executable": [".exe", ".dll", ".scr", ".pif", ".com", ".msi", ".jar", ".class"],
    "script": [".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".wsh", ".hta"],
    "document": [".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pptm", ".pdf", ".rtf"],
    "archive": [".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".cab"],
    "image": [".jpg", ".jpeg", ".png", ".gif", ".bmp", ".ico", ".svg", ".webp"],
    "audio": [".mp3", ".wav", ".ogg", ".flac", ".aac", ".wma"],
    "video": [".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm"],
    "data": [".json", ".xml", ".csv", ".yaml", ".yml", ".ini", ".conf", ".cfg"],
}

# Suspicious extensions that could be malware
SUSPICIOUS_EXTENSIONS = [
    ".exe", ".dll", ".scr", ".pif", ".com", ".msi",
    ".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".wsh", ".hta",
    ".docm", ".xlsm", ".pptm",  # Macro-enabled Office
    ".jar", ".class",
]


@dataclass
class HashRecord:
    """Structured hash record for investigation."""
    sha256: str
    sha1: str
    md5: str
    file_path: str
    filename: str
    extension: str
    file_size: int
    file_category: str
    is_suspicious: bool
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    protocol: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.now)
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class FileHasher:
    """File hashing utilities with metadata extraction."""

    def __init__(self):
        """Initialize file hasher."""
        self._supported_algorithms = ["md5", "sha1", "sha256", "sha512"]

    @property
    def supported_algorithms(self) -> List[str]:
        """Get list of supported hash algorithms."""
        return self._supported_algorithms.copy()

    def compute_sha256(self, file_path: str) -> str:
        """Compute SHA256 hash of file.

        Args:
            file_path: Path to file

        Returns:
            SHA256 hex string
        """
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()

    def compute_hashes(
        self,
        file_path: str,
        algorithms: Optional[List[str]] = None
    ) -> Dict[str, str]:
        """Compute multiple hash algorithms for file.

        Args:
            file_path: Path to file
            algorithms: List of algorithms (default: md5, sha1, sha256)

        Returns:
            Dictionary mapping algorithm name to hash
        """
        if algorithms is None:
            algorithms = ["md5", "sha1", "sha256"]

        # Validate algorithms
        algorithms = [a.lower() for a in algorithms]
        for alg in algorithms:
            if alg not in self._supported_algorithms:
                raise ValueError(f"Unsupported algorithm: {alg}")

        # Create hash objects
        hash_objects = {}
        for alg in algorithms:
            hash_objects[alg] = hashlib.new(alg)

        # Read file once, update all hashes
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                for hash_obj in hash_objects.values():
                    hash_obj.update(chunk)

        # Return hex digests
        return {alg: hash_obj.hexdigest() for alg, hash_obj in hash_objects.items()}

    def hash_with_metadata(self, file_path: str) -> Dict[str, Any]:
        """Compute hash with full file metadata.

        Args:
            file_path: Path to file

        Returns:
            Dictionary with hash and metadata
        """
        path = Path(file_path)
        stat = os.stat(file_path)

        hashes = self.compute_hashes(file_path, ["sha256"])
        extension = path.suffix.lower()

        return {
            "sha256": hashes["sha256"],
            "file_path": str(path.absolute()),
            "filename": path.name,
            "extension": extension,
            "file_size": stat.st_size,
            "file_category": self.get_file_category(path.name),
            "is_suspicious": self.is_suspicious_extension(path.name),
            "modified_time": datetime.fromtimestamp(stat.st_mtime),
            "created_time": datetime.fromtimestamp(stat.st_ctime),
        }

    def get_file_category(self, filename: str) -> str:
        """Get file category by extension.

        Args:
            filename: Filename with extension

        Returns:
            Category string (executable, script, document, etc.)
        """
        ext = Path(filename).suffix.lower()

        for category, extensions in FILE_CATEGORIES.items():
            if ext in extensions:
                return category

        return "unknown"

    def is_suspicious_extension(self, filename: str) -> bool:
        """Check if file has suspicious extension.

        Args:
            filename: Filename with extension

        Returns:
            True if extension is suspicious
        """
        ext = Path(filename).suffix.lower()
        return ext in SUSPICIOUS_EXTENSIONS

    def hash_buffer(
        self,
        data: bytes,
        algorithms: Optional[List[str]] = None
    ) -> Dict[str, str]:
        """Hash raw bytes buffer.

        Args:
            data: Bytes to hash
            algorithms: List of algorithms (default: sha256)

        Returns:
            Dictionary mapping algorithm name to hash
        """
        if algorithms is None:
            algorithms = ["sha256"]

        result = {}
        for alg in algorithms:
            if alg not in self._supported_algorithms:
                raise ValueError(f"Unsupported algorithm: {alg}")
            result[alg] = hashlib.new(alg, data).hexdigest()

        return result

    def batch_hash(
        self,
        file_paths: List[str],
        algorithms: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """Hash multiple files in batch.

        Args:
            file_paths: List of file paths
            algorithms: Hash algorithms to use

        Returns:
            List of hash result dictionaries
        """
        if algorithms is None:
            algorithms = ["sha256"]

        results = []
        for file_path in file_paths:
            try:
                path = Path(file_path)
                hashes = self.compute_hashes(file_path, algorithms)
                results.append({
                    **hashes,
                    "file_path": str(path.absolute()),
                    "filename": path.name,
                    "file_size": os.path.getsize(file_path),
                    "success": True,
                })
            except Exception as e:
                logger.warning(f"Failed to hash {file_path}: {e}")
                results.append({
                    "file_path": file_path,
                    "success": False,
                    "error": str(e),
                })

        return results

    def create_hash_record(
        self,
        file_path: str,
        source_ip: Optional[str] = None,
        dest_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> HashRecord:
        """Create structured hash record for investigation.

        Args:
            file_path: Path to file
            source_ip: Source IP address
            dest_ip: Destination IP address
            protocol: Network protocol
            tags: Optional tags for categorization
            metadata: Additional metadata

        Returns:
            HashRecord instance
        """
        path = Path(file_path)
        hashes = self.compute_hashes(file_path, ["md5", "sha1", "sha256"])
        extension = path.suffix.lower()

        return HashRecord(
            sha256=hashes["sha256"],
            sha1=hashes["sha1"],
            md5=hashes["md5"],
            file_path=str(path.absolute()),
            filename=path.name,
            extension=extension,
            file_size=os.path.getsize(file_path),
            file_category=self.get_file_category(path.name),
            is_suspicious=self.is_suspicious_extension(path.name),
            source_ip=source_ip,
            dest_ip=dest_ip,
            protocol=protocol,
            tags=tags or [],
            metadata=metadata or {},
        )

    def format_for_lookup(self, file_path: str) -> Dict[str, Any]:
        """Format hash data for threat intel lookup (VirusTotal-style).

        Args:
            file_path: Path to file

        Returns:
            Dictionary formatted for lookup services
        """
        path = Path(file_path)
        hashes = self.compute_hashes(file_path, ["md5", "sha1", "sha256"])

        return {
            "md5": hashes["md5"],
            "sha1": hashes["sha1"],
            "sha256": hashes["sha256"],
            "file_size": os.path.getsize(file_path),
            "filename": path.name,
            "extension": path.suffix.lower(),
            "file_category": self.get_file_category(path.name),
        }

    def compare_hashes(self, hash1: str, hash2: str) -> bool:
        """Compare two hashes in constant time to prevent timing attacks.

        Args:
            hash1: First hash
            hash2: Second hash

        Returns:
            True if hashes match
        """
        import hmac
        return hmac.compare_digest(hash1.lower(), hash2.lower())

    def get_hash_summary(self, results: List[Dict]) -> str:
        """Generate human-readable hash summary.

        Args:
            results: List of hash results

        Returns:
            Summary string
        """
        lines = []
        lines.append("=" * 60)
        lines.append(" FILE HASH SUMMARY")
        lines.append("=" * 60)
        lines.append("")

        success_count = sum(1 for r in results if r.get("success", True))
        lines.append(f"Total Files: {len(results)}")
        lines.append(f"Successfully Hashed: {success_count}")
        lines.append("")

        # Group by category
        by_category = {}
        for result in results:
            if not result.get("success", True):
                continue
            filename = result.get("filename", "unknown")
            category = self.get_file_category(filename)
            by_category.setdefault(category, []).append(result)

        for category, items in sorted(by_category.items()):
            lines.append(f"  {category.upper()}: {len(items)} files")
            for item in items[:3]:
                lines.append(f"    - {item.get('filename', 'unknown')}")
                lines.append(f"      SHA256: {item.get('sha256', 'N/A')[:32]}...")
            if len(items) > 3:
                lines.append(f"    ... and {len(items) - 3} more")

        lines.append("")
        lines.append("=" * 60)

        return "\n".join(lines)
