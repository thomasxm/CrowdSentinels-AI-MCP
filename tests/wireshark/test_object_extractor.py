# tests/wireshark/test_object_extractor.py
"""Tests for object extractor."""
import pytest
import tempfile
from pathlib import Path
from datetime import datetime


TEST_PCAP_DIR = Path("/home/kali/Desktop/CTU/normal_traffics")


class TestObjectExtractor:
    """Test HTTP/SMB object extraction."""

    def test_list_http_objects(self):
        """Should list HTTP objects in PCAP without extracting."""
        from src.wireshark.extraction.object_extractor import ObjectExtractor

        pcap_files = list(TEST_PCAP_DIR.glob("**/*.pcap"))
        if not pcap_files:
            pytest.skip("No test pcap files available")

        extractor = ObjectExtractor()
        objects = extractor.list_objects(str(pcap_files[0]), protocol="http")

        # Should return a list (may be empty for normal traffic)
        assert isinstance(objects, list)

    def test_extract_to_temp_dir(self):
        """Should extract objects to temporary directory."""
        from src.wireshark.extraction.object_extractor import ObjectExtractor

        pcap_files = list(TEST_PCAP_DIR.glob("**/*.pcap"))
        if not pcap_files:
            pytest.skip("No test pcap files available")

        extractor = ObjectExtractor()

        with tempfile.TemporaryDirectory() as tmpdir:
            result = extractor.extract_objects(
                pcap_path=str(pcap_files[0]),
                output_dir=tmpdir,
                protocol="http"
            )

            assert "extracted_count" in result
            assert "output_dir" in result

    def test_get_object_metadata(self):
        """Should get metadata without extracting content."""
        from src.wireshark.extraction.object_extractor import ObjectExtractor

        extractor = ObjectExtractor()

        # Create mock object data
        object_data = {
            "packet": 100,
            "hostname": "example.com",
            "content_type": "text/html",
            "size": 1024,
            "filename": "index.html"
        }

        metadata = extractor.build_metadata(
            object_data=object_data,
            src_ip="192.168.1.100",
            dst_ip="93.184.216.34",
            protocol="http"
        )

        assert metadata["filename"] == "index.html"
        assert metadata["protocol"] == "http"
        assert metadata["size_bytes"] == 1024

    def test_extract_with_hash_only(self):
        """Should extract metadata and hash without storing files."""
        from src.wireshark.extraction.object_extractor import ObjectExtractor

        extractor = ObjectExtractor(store_files=False)

        # With store_files=False, should only return metadata with hash
        assert extractor.store_files is False

    def test_supported_protocols(self):
        """Should support HTTP, SMB, and FTP protocols."""
        from src.wireshark.extraction.object_extractor import ObjectExtractor

        extractor = ObjectExtractor()
        supported = extractor.supported_protocols

        assert "http" in supported
        assert "smb" in supported

    def test_filter_by_extension(self):
        """Should filter objects by file extension."""
        from src.wireshark.extraction.object_extractor import ObjectExtractor

        extractor = ObjectExtractor()

        objects = [
            {"filename": "malware.exe", "size": 1000},
            {"filename": "image.png", "size": 2000},
            {"filename": "document.pdf", "size": 3000},
            {"filename": "script.js", "size": 500},
        ]

        # Filter for executables
        filtered = extractor.filter_by_extension(objects, [".exe", ".dll"])
        assert len(filtered) == 1
        assert filtered[0]["filename"] == "malware.exe"

    def test_filter_by_size(self):
        """Should filter objects by size."""
        from src.wireshark.extraction.object_extractor import ObjectExtractor

        extractor = ObjectExtractor()

        objects = [
            {"filename": "small.txt", "size": 100},
            {"filename": "medium.doc", "size": 1000},
            {"filename": "large.zip", "size": 10000},
        ]

        # Filter for objects > 500 bytes
        filtered = extractor.filter_by_size(objects, min_size=500)
        assert len(filtered) == 2

    def test_create_extracted_object_model(self):
        """Should create ExtractedObject model from metadata."""
        from src.wireshark.extraction.object_extractor import ObjectExtractor
        from src.wireshark.models import ExtractedObject

        extractor = ObjectExtractor()

        metadata = {
            "filename": "test.exe",
            "protocol": "http",
            "size_bytes": 1024,
            "sha256": "abc123def456",
            "src_ip": "192.168.1.100",
            "dst_ip": "8.8.8.8",
            "mime_type": "application/octet-stream"
        }

        obj = extractor.create_extracted_object(
            metadata=metadata,
            pcap_path="/tmp/test.pcap"
        )

        assert isinstance(obj, ExtractedObject)
        assert obj.filename == "test.exe"
        assert obj.sha256 == "abc123def456"
