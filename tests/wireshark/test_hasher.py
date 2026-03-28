# tests/wireshark/test_hasher.py
"""Tests for file hasher module."""

import tempfile
from pathlib import Path


class TestFileHasher:
    """Test file hashing utilities."""

    def test_compute_sha256(self):
        """Should compute SHA256 hash of file."""
        from src.wireshark.extraction.hasher import FileHasher

        hasher = FileHasher()

        # Create temp file with known content
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            f.write(b"test content for hashing")
            temp_path = f.name

        try:
            result = hasher.compute_sha256(temp_path)
            assert len(result) == 64  # SHA256 hex string
            # Known hash for "test content for hashing"
            assert result == "e25dd806d495b413931f4eea50b677a7a5c02d00460924661283f211a37f7e7f"
        finally:
            Path(temp_path).unlink()

    def test_compute_multiple_hashes(self):
        """Should compute multiple hash algorithms."""
        from src.wireshark.extraction.hasher import FileHasher

        hasher = FileHasher()

        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            f.write(b"test")
            temp_path = f.name

        try:
            result = hasher.compute_hashes(temp_path, algorithms=["md5", "sha1", "sha256"])
            assert "md5" in result
            assert "sha1" in result
            assert "sha256" in result
            assert len(result["md5"]) == 32  # MD5 hex length
            assert len(result["sha1"]) == 40  # SHA1 hex length
            assert len(result["sha256"]) == 64  # SHA256 hex length
        finally:
            Path(temp_path).unlink()

    def test_compute_hash_with_metadata(self):
        """Should compute hash with full metadata."""
        from src.wireshark.extraction.hasher import FileHasher

        hasher = FileHasher()

        with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
            f.write(b"MZ" + b"\x00" * 100)  # Fake PE header
            temp_path = f.name

        try:
            result = hasher.hash_with_metadata(temp_path)

            assert "sha256" in result
            assert "file_size" in result
            assert "filename" in result
            assert "extension" in result
            assert result["extension"] == ".exe"
            assert result["file_size"] == 102
        finally:
            Path(temp_path).unlink()

    def test_detect_file_type_by_extension(self):
        """Should detect file type by extension."""
        from src.wireshark.extraction.hasher import FileHasher

        hasher = FileHasher()

        assert hasher.get_file_category("malware.exe") == "executable"
        assert hasher.get_file_category("document.pdf") == "document"
        assert hasher.get_file_category("image.png") == "image"
        assert hasher.get_file_category("script.ps1") == "script"
        assert hasher.get_file_category("archive.zip") == "archive"
        assert hasher.get_file_category("unknown.xyz") == "unknown"

    def test_is_suspicious_extension(self):
        """Should identify suspicious file extensions."""
        from src.wireshark.extraction.hasher import FileHasher

        hasher = FileHasher()

        # Suspicious
        assert hasher.is_suspicious_extension("payload.exe") is True
        assert hasher.is_suspicious_extension("script.ps1") is True
        assert hasher.is_suspicious_extension("macro.docm") is True
        assert hasher.is_suspicious_extension("backdoor.dll") is True

        # Not suspicious
        assert hasher.is_suspicious_extension("image.png") is False
        assert hasher.is_suspicious_extension("document.pdf") is False
        assert hasher.is_suspicious_extension("data.json") is False

    def test_hash_buffer(self):
        """Should hash raw bytes buffer."""
        from src.wireshark.extraction.hasher import FileHasher

        hasher = FileHasher()

        data = b"test buffer content"
        result = hasher.hash_buffer(data)

        assert "sha256" in result
        assert len(result["sha256"]) == 64

    def test_batch_hash_files(self):
        """Should hash multiple files in batch."""
        from src.wireshark.extraction.hasher import FileHasher

        hasher = FileHasher()

        # Create temp files
        temp_files = []
        try:
            for i in range(3):
                with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
                    f.write(f"content {i}".encode())
                    temp_files.append(f.name)

            results = hasher.batch_hash(temp_files)

            assert len(results) == 3
            assert all("sha256" in r for r in results)
            # Each file has different content, so different hashes
            hashes = [r["sha256"] for r in results]
            assert len(set(hashes)) == 3  # All unique

        finally:
            for path in temp_files:
                Path(path).unlink()

    def test_create_hash_record(self):
        """Should create structured hash record for investigation."""
        from src.wireshark.extraction.hasher import FileHasher, HashRecord

        hasher = FileHasher()

        with tempfile.NamedTemporaryFile(mode="wb", suffix=".exe", delete=False) as f:
            f.write(b"MZ" + b"\x00" * 100)
            temp_path = f.name

        try:
            record = hasher.create_hash_record(
                file_path=temp_path, source_ip="192.168.1.100", dest_ip="203.0.113.42", protocol="http"
            )

            assert isinstance(record, HashRecord)
            assert record.sha256 is not None
            assert record.source_ip == "192.168.1.100"
            assert record.dest_ip == "203.0.113.42"
            assert record.protocol == "http"
            assert record.is_suspicious is True  # .exe is suspicious

        finally:
            Path(temp_path).unlink()

    def test_format_for_virustotal(self):
        """Should format hash for VirusTotal lookup structure."""
        from src.wireshark.extraction.hasher import FileHasher

        hasher = FileHasher()

        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            f.write(b"test content")
            temp_path = f.name

        try:
            vt_format = hasher.format_for_lookup(temp_path)

            assert "sha256" in vt_format
            assert "sha1" in vt_format
            assert "md5" in vt_format
            assert "file_size" in vt_format
            assert "filename" in vt_format

        finally:
            Path(temp_path).unlink()
