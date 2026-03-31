"""Tests for SmartExtractor.extract_iocs_from_velociraptor()."""

import pytest

from src.storage.models import IoCType, SourceType
from src.storage.smart_extractor import SmartExtractor


@pytest.fixture
def extractor():
    return SmartExtractor(max_iocs=100, max_events=50)


class TestExtractIocsFromVelociraptor:
    """Test IoC extraction from various Velociraptor artifact result formats."""

    def test_extract_from_pslist(self, extractor):
        """Process listing should yield PROCESS and COMMANDLINE IoCs."""
        results = {
            "events": [
                {
                    "Name": "powershell.exe",
                    "Exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "CommandLine": "powershell -EncodedCommand ZQBjAGgAbwAgACIASABl",
                    "Username": "CORP\\jdoe",
                    "Pid": 1234,
                },
                {
                    "Name": "cmd.exe",
                    "Exe": "C:\\Windows\\System32\\cmd.exe",
                    "CommandLine": "cmd.exe /c whoami",
                    "Username": "CORP\\admin",
                    "Pid": 5678,
                },
            ]
        }

        iocs = extractor.extract_iocs_from_velociraptor(results, "velociraptor_pslist")

        types = {ioc.type for ioc in iocs}
        assert IoCType.PROCESS in types
        assert IoCType.COMMANDLINE in types
        assert IoCType.USER in types

        # Check process names extracted
        process_values = {ioc.value for ioc in iocs if ioc.type == IoCType.PROCESS}
        assert "powershell.exe" in process_values

        # Check source type
        for ioc in iocs:
            assert ioc.sources[0].source_type == SourceType.VELOCIRAPTOR

    def test_extract_from_netstat(self, extractor):
        """Network connections should yield IP IoCs."""
        results = [
            {
                "Raddr": "203.0.113.50",
                "Rport": 443,
                "Laddr": "192.168.1.10",
                "Name": "chrome.exe",
                "Username": "user1",
                "Status": "ESTABLISHED",
            },
        ]

        iocs = extractor.extract_iocs_from_velociraptor(results, "velociraptor_netstat")

        ip_iocs = [ioc for ioc in iocs if ioc.type == IoCType.IP]
        assert len(ip_iocs) >= 1
        ip_values = {ioc.value for ioc in ip_iocs}
        assert "203.0.113.50" in ip_values

    def test_extract_from_services(self, extractor):
        """Services should yield SERVICE, FILE_PATH, and HASH IoCs."""
        results = {
            "events": [
                {
                    "DisplayName": "Suspicious Service",
                    "AbsoluteExePath": "C:\\ProgramData\\malware\\svc.exe",
                    "HashServiceExe": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                    "UserAccount": "LocalSystem",
                },
            ]
        }

        iocs = extractor.extract_iocs_from_velociraptor(results, "velociraptor_services")

        types = {ioc.type for ioc in iocs}
        assert IoCType.FILE_PATH in types
        assert IoCType.HASH in types

    def test_extract_from_evidence_of_download(self, extractor):
        """Download evidence should yield URL, HASH, and FILE_PATH IoCs."""
        results = {
            "events": [
                {
                    "DownloadedFilePath": "C:\\Users\\jdoe\\Downloads\\payload.exe",
                    "FileHash": "abc123def456abc123def456abc123de",
                    "HostUrl": "https://evil.example.com/payload.exe",
                    "ReferrerUrl": "https://phishing.example.com/click",
                },
            ]
        }

        iocs = extractor.extract_iocs_from_velociraptor(results, "velociraptor_evidence_of_download")

        types = {ioc.type for ioc in iocs}
        assert IoCType.FILE_PATH in types
        assert IoCType.URL in types
        assert IoCType.HASH in types

    def test_extract_from_amcache(self, extractor):
        """Amcache should yield FILE_PATH, HASH, and PROCESS IoCs."""
        results = {
            "events": [
                {
                    "FullPath": "C:\\Temp\\mimikatz.exe",
                    "SHA1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                    "Publisher": "Unknown",
                    "FileDescription": "mimikatz",
                },
            ]
        }

        iocs = extractor.extract_iocs_from_velociraptor(results, "velociraptor_amcache")

        types = {ioc.type for ioc in iocs}
        assert IoCType.FILE_PATH in types
        assert IoCType.HASH in types

    def test_extract_from_registry_artifacts(self, extractor):
        """Registry artifacts (shellbags, recentdocs) should yield REGISTRY_KEY IoCs."""
        results = {
            "events": [
                {
                    "Key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware",
                    "KeyPath": "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    "Path": "C:\\Users\\Public\\malware.exe",
                },
            ]
        }

        iocs = extractor.extract_iocs_from_velociraptor(results, "velociraptor_shellbags")

        types = {ioc.type for ioc in iocs}
        assert IoCType.REGISTRY_KEY in types

    def test_empty_results_returns_empty(self, extractor):
        """Empty results should return empty IoC list."""
        assert extractor.extract_iocs_from_velociraptor({}, "test") == []
        assert extractor.extract_iocs_from_velociraptor({"events": []}, "test") == []
        assert extractor.extract_iocs_from_velociraptor([], "test") == []

    def test_deduplication(self, extractor):
        """Duplicate IoCs should be merged."""
        results = [
            {"Name": "powershell.exe", "Username": "admin"},
            {"Name": "powershell.exe", "Username": "admin"},
            {"Name": "powershell.exe", "Username": "admin"},
        ]

        iocs = extractor.extract_iocs_from_velociraptor(results, "test")

        # powershell.exe should appear once (deduplicated)
        process_iocs = [ioc for ioc in iocs if ioc.type == IoCType.PROCESS and ioc.value == "powershell.exe"]
        assert len(process_iocs) == 1

    def test_skips_system_users(self, extractor):
        """System accounts like SYSTEM should be filtered out."""
        results = [{"Username": "SYSTEM"}, {"Username": "LOCAL SERVICE"}]

        iocs = extractor.extract_iocs_from_velociraptor(results, "test")

        user_iocs = [ioc for ioc in iocs if ioc.type == IoCType.USER]
        assert len(user_iocs) == 0

    def test_skips_loopback_ips(self, extractor):
        """Loopback and zero IPs should be filtered out."""
        results = [{"Raddr": "127.0.0.1"}, {"Raddr": "0.0.0.0"}, {"Laddr": "::1"}]

        iocs = extractor.extract_iocs_from_velociraptor(results, "test")

        ip_iocs = [ioc for ioc in iocs if ioc.type == IoCType.IP]
        assert len(ip_iocs) == 0

    def test_pyramid_priority_assigned(self, extractor):
        """IoCs should have Pyramid of Pain priority correctly assigned."""
        results = [
            {"Raddr": "10.0.0.5"},  # IP → priority 2
            {"Name": "mimikatz.exe"},  # PROCESS → priority 5
            {"CommandLine": "powershell -enc AAAA"},  # COMMANDLINE → priority 6
        ]

        iocs = extractor.extract_iocs_from_velociraptor(results, "test")

        for ioc in iocs:
            if ioc.type == IoCType.IP:
                assert ioc.pyramid_priority == 2
            elif ioc.type == IoCType.PROCESS:
                assert ioc.pyramid_priority == 5
            elif ioc.type == IoCType.COMMANDLINE:
                assert ioc.pyramid_priority == 6

    def test_handles_list_results_directly(self, extractor):
        """Should handle raw list results (common Velociraptor format)."""
        results = [
            {"Name": "svchost.exe", "Hostname": "DC01"},
            {"Name": "explorer.exe", "Hostname": "WS01"},
        ]

        iocs = extractor.extract_iocs_from_velociraptor(results, "test")
        assert len(iocs) > 0

    def test_handles_dict_with_response_key(self, extractor):
        """Should handle dict with 'response' key wrapping a list."""
        results = {
            "response": [
                {"Name": "calc.exe", "Username": "testuser"},
            ]
        }

        iocs = extractor.extract_iocs_from_velociraptor(results, "test")
        process_values = {ioc.value for ioc in iocs if ioc.type == IoCType.PROCESS}
        assert "calc.exe" in process_values
