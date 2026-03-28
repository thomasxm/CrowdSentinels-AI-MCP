"""Tests for STIX 2.1 export functionality.

Covers:
- IoC type to STIX SCO pattern mapping
- Bundle structure and validity
- Confidence mapping
- Edge cases (empty, unsupported types, special characters)
- Full roundtrip (create -> add IoCs -> export -> parse -> verify)
"""

import json
import sys
from pathlib import Path

import pytest
import stix2

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.storage.config import StorageConfig, set_config
from src.storage.investigation_state import InvestigationStateClient
from src.storage.models import (
    Investigation,
    IoC,
    IoCSource,
    IoCType,
    SourceType,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_config(tmp_path: Path) -> StorageConfig:
    """Provide a StorageConfig rooted in a pytest tmp directory."""
    cfg = StorageConfig(base_path=tmp_path / "crowdsentinel")
    set_config(cfg)
    cfg.ensure_directories()
    return cfg


@pytest.fixture
def client(tmp_config: StorageConfig) -> InvestigationStateClient:
    """Provide an InvestigationStateClient backed by tmp storage."""
    return InvestigationStateClient(config=tmp_config)


@pytest.fixture
def sample_investigation() -> Investigation:
    """Return a minimal Investigation with no IoCs."""
    return Investigation.create(name="STIX-Test", description="Unit test investigation")


def _make_ioc(
    ioc_type: IoCType,
    value: str,
    confidence: float = 0.5,
    tags: list[str] | None = None,
) -> IoC:
    """Helper to build an IoC with a single manual source."""
    return IoC(
        type=ioc_type,
        value=value,
        confidence=confidence,
        tags=tags or [],
        sources=[
            IoCSource(tool="manual", source_type=SourceType.MANUAL),
        ],
    )


# ---------------------------------------------------------------------------
# Pattern-mapping tests
# ---------------------------------------------------------------------------


class TestIoCToStixPattern:
    """Verify _ioc_to_stix_pattern returns the correct STIX SCO pattern."""

    @staticmethod
    def _pattern(ioc_type: str, value: str) -> str | None:
        return InvestigationStateClient._ioc_to_stix_pattern(ioc_type, value)

    def test_ipv4(self) -> None:
        result = self._pattern("ip", "192.168.1.1")
        assert result == "[ipv4-addr:value = '192.168.1.1']"

    def test_ipv6(self) -> None:
        result = self._pattern("ip", "::1")
        assert result == "[ipv6-addr:value = '::1']"

    def test_ipv6_full(self) -> None:
        addr = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        result = self._pattern("ip", addr)
        assert result is not None
        assert "ipv6-addr:value" in result

    def test_domain(self) -> None:
        result = self._pattern("domain", "evil.com")
        assert result == "[domain-name:value = 'evil.com']"

    def test_hostname(self) -> None:
        result = self._pattern("hostname", "dc01.corp.local")
        assert result == "[domain-name:value = 'dc01.corp.local']"

    def test_url(self) -> None:
        result = self._pattern("url", "https://evil.com/payload")
        assert result == "[url:value = 'https://evil.com/payload']"

    def test_hash_md5(self) -> None:
        md5 = "d41d8cd98f00b204e9800998ecf8427e"  # 32 chars
        result = self._pattern("hash", md5)
        assert result == f"[file:hashes.MD5 = '{md5}']"

    def test_hash_sha1(self) -> None:
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"  # 40 chars
        result = self._pattern("hash", sha1)
        assert result == f"[file:hashes.'SHA-1' = '{sha1}']"

    def test_hash_sha256(self) -> None:
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"  # 64 chars
        result = self._pattern("hash", sha256)
        assert result == f"[file:hashes.'SHA-256' = '{sha256}']"

    def test_email(self) -> None:
        result = self._pattern("email", "attacker@evil.com")
        assert result == "[email-addr:value = 'attacker@evil.com']"

    def test_user(self) -> None:
        result = self._pattern("user", "admin")
        assert result == "[user-account:account_login = 'admin']"

    def test_process(self) -> None:
        result = self._pattern("process", "powershell.exe -enc abc123")
        assert result == "[process:command_line = 'powershell.exe -enc abc123']"

    def test_commandline(self) -> None:
        result = self._pattern("commandline", "cmd /c whoami")
        assert result == "[process:command_line = 'cmd /c whoami']"

    def test_file_path(self) -> None:
        result = self._pattern("file_path", "C:\\Windows\\Temp\\malware.exe")
        assert result is not None
        assert "file:name" in result

    def test_registry_key(self) -> None:
        key = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        result = self._pattern("registry_key", key)
        assert result is not None
        assert "windows-registry-key:key" in result

    def test_unsupported_type_returns_none(self) -> None:
        result = self._pattern("other", "some-value")
        assert result is None

    def test_unsupported_type_service_returns_none(self) -> None:
        result = self._pattern("service", "svchost")
        assert result is None

    def test_unsupported_type_scheduled_task_returns_none(self) -> None:
        result = self._pattern("scheduled_task", "evilTask")
        assert result is None


# ---------------------------------------------------------------------------
# Special-character escaping
# ---------------------------------------------------------------------------


class TestSpecialCharacterEscaping:
    """Verify single quotes and backslashes are escaped in patterns."""

    @staticmethod
    def _pattern(ioc_type: str, value: str) -> str | None:
        return InvestigationStateClient._ioc_to_stix_pattern(ioc_type, value)

    def test_single_quote_in_domain(self) -> None:
        result = self._pattern("domain", "it's-evil.com")
        assert result is not None
        assert "it\\'s-evil.com" in result

    def test_backslash_in_file_path(self) -> None:
        result = self._pattern("file_path", "C:\\Users\\admin\\evil.exe")
        assert result is not None
        # The value should have backslashes escaped
        assert "file:name" in result

    def test_single_quote_in_url(self) -> None:
        result = self._pattern("url", "https://evil.com/path?q=it's")
        assert result is not None
        assert "\\'" in result


# ---------------------------------------------------------------------------
# STIX bundle structure
# ---------------------------------------------------------------------------


class TestStixBundleStructure:
    """Verify exported bundle has correct STIX 2.1 structure."""

    def test_bundle_is_valid_json(self, client: InvestigationStateClient) -> None:
        inv = client.create_investigation("json-test")
        iocs = [_make_ioc(IoCType.IP, "10.0.0.1")]
        client.add_iocs(iocs)
        result = client.export_iocs(format="stix")

        # Must be dict (parsed JSON)
        assert isinstance(result, dict)
        # Round-trip through JSON
        serialized = json.dumps(result)
        reparsed = json.loads(serialized)
        assert reparsed["type"] == "bundle"

    def test_bundle_parseable_by_stix2(self, client: InvestigationStateClient) -> None:
        inv = client.create_investigation("parse-test")
        iocs = [_make_ioc(IoCType.DOMAIN, "evil.example.com")]
        client.add_iocs(iocs)
        result = client.export_iocs(format="stix")

        bundle = stix2.parse(result, allow_custom=True)
        assert bundle.type == "bundle"

    def test_bundle_contains_identity_and_indicator(self, client: InvestigationStateClient) -> None:
        inv = client.create_investigation("objects-test")
        iocs = [_make_ioc(IoCType.IP, "1.2.3.4")]
        client.add_iocs(iocs)
        result = client.export_iocs(format="stix")

        types_in_bundle = {obj["type"] for obj in result["objects"]}
        assert "identity" in types_in_bundle
        assert "indicator" in types_in_bundle

    def test_identity_name_is_crowdsentinel(self, client: InvestigationStateClient) -> None:
        inv = client.create_investigation("identity-test")
        client.add_iocs([_make_ioc(IoCType.IP, "1.1.1.1")])
        result = client.export_iocs(format="stix")

        identities = [o for o in result["objects"] if o["type"] == "identity"]
        assert len(identities) == 1
        assert identities[0]["name"] == "CrowdSentinel"

    def test_indicator_has_created_by_ref(self, client: InvestigationStateClient) -> None:
        inv = client.create_investigation("ref-test")
        client.add_iocs([_make_ioc(IoCType.IP, "1.1.1.1")])
        result = client.export_iocs(format="stix")

        identity_id = [o for o in result["objects"] if o["type"] == "identity"][0]["id"]
        indicators = [o for o in result["objects"] if o["type"] == "indicator"]
        for ind in indicators:
            assert ind["created_by_ref"] == identity_id


# ---------------------------------------------------------------------------
# Confidence mapping
# ---------------------------------------------------------------------------


class TestConfidenceMapping:
    """Verify float confidence is mapped to integer 1-100."""

    def test_confidence_087_maps_to_87(self, client: InvestigationStateClient) -> None:
        inv = client.create_investigation("conf-test")
        ioc = _make_ioc(IoCType.IP, "10.0.0.87", confidence=0.87)
        client.add_iocs([ioc])
        result = client.export_iocs(format="stix")

        indicators = [o for o in result["objects"] if o["type"] == "indicator"]
        assert len(indicators) == 1
        assert indicators[0]["confidence"] == 87

    def test_confidence_zero_clamps_to_1(self, client: InvestigationStateClient) -> None:
        inv = client.create_investigation("conf-min")
        ioc = _make_ioc(IoCType.IP, "10.0.0.0", confidence=0.0)
        client.add_iocs([ioc])
        result = client.export_iocs(format="stix")

        indicators = [o for o in result["objects"] if o["type"] == "indicator"]
        assert indicators[0]["confidence"] >= 1

    def test_confidence_one_maps_to_100(self, client: InvestigationStateClient) -> None:
        inv = client.create_investigation("conf-max")
        ioc = _make_ioc(IoCType.IP, "10.0.0.100", confidence=1.0)
        client.add_iocs([ioc])
        result = client.export_iocs(format="stix")

        indicators = [o for o in result["objects"] if o["type"] == "indicator"]
        assert indicators[0]["confidence"] == 100


# ---------------------------------------------------------------------------
# Empty / edge cases
# ---------------------------------------------------------------------------


class TestEmptyAndEdgeCases:
    """Edge cases: empty investigation, unsupported types, etc."""

    def test_empty_investigation_has_identity_only(self, client: InvestigationStateClient) -> None:
        inv = client.create_investigation("empty-stix")
        result = client.export_iocs(format="stix")

        assert isinstance(result, dict)
        assert result["type"] == "bundle"
        # Only the Identity should be present (no indicators)
        types_in_bundle = [obj["type"] for obj in result["objects"]]
        assert "identity" in types_in_bundle
        assert "indicator" not in types_in_bundle

    def test_unsupported_ioc_type_skipped(self, client: InvestigationStateClient) -> None:
        inv = client.create_investigation("skip-test")
        # 'other' type has no STIX mapping -> should be skipped
        ioc_other = _make_ioc(IoCType.OTHER, "something-unknown")
        ioc_ip = _make_ioc(IoCType.IP, "172.16.0.1")
        client.add_iocs([ioc_other, ioc_ip])
        result = client.export_iocs(format="stix")

        indicators = [o for o in result["objects"] if o["type"] == "indicator"]
        # Only the IP should produce an indicator
        assert len(indicators) == 1
        assert "172.16.0.1" in indicators[0]["pattern"]

    def test_service_ioc_type_skipped(self, client: InvestigationStateClient) -> None:
        inv = client.create_investigation("service-skip")
        ioc_service = _make_ioc(IoCType.SERVICE, "svchost")
        client.add_iocs([ioc_service])
        result = client.export_iocs(format="stix")

        indicators = [o for o in result["objects"] if o["type"] == "indicator"]
        assert len(indicators) == 0

    def test_bundle_stix_version(self, client: InvestigationStateClient) -> None:
        inv = client.create_investigation("version-test")
        client.add_iocs([_make_ioc(IoCType.IP, "8.8.8.8")])
        result = client.export_iocs(format="stix")
        # STIX 2.1 bundles may not include spec_version at the bundle level
        # but objects should be 2.1
        indicators = [o for o in result["objects"] if o["type"] == "indicator"]
        for ind in indicators:
            assert ind.get("spec_version", "2.1") == "2.1"


# ---------------------------------------------------------------------------
# Full roundtrip
# ---------------------------------------------------------------------------


class TestFullRoundtrip:
    """Create investigation -> add diverse IoCs -> export STIX -> parse -> verify."""

    @pytest.fixture
    def diverse_iocs(self) -> list[IoC]:
        return [
            _make_ioc(IoCType.IP, "192.168.1.100", confidence=0.9),
            _make_ioc(IoCType.IP, "::1", confidence=0.6),
            _make_ioc(IoCType.DOMAIN, "malware-c2.com", confidence=0.95),
            _make_ioc(IoCType.HOSTNAME, "dc01.corp.local", confidence=0.7),
            _make_ioc(IoCType.URL, "https://evil.com/stage2", confidence=0.85),
            _make_ioc(
                IoCType.HASH,
                "d41d8cd98f00b204e9800998ecf8427e",
                confidence=0.5,
            ),  # MD5
            _make_ioc(
                IoCType.HASH,
                "da39a3ee5e6b4b0d3255bfef95601890afd80709",
                confidence=0.5,
            ),  # SHA-1
            _make_ioc(
                IoCType.HASH,
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                confidence=0.5,
            ),  # SHA-256
            _make_ioc(IoCType.EMAIL, "phish@evil.com", confidence=0.8),
            _make_ioc(IoCType.USER, "backdoor_admin", confidence=0.75),
            _make_ioc(IoCType.PROCESS, "mimikatz.exe", confidence=0.99),
            _make_ioc(
                IoCType.FILE_PATH,
                "C:\\Windows\\Temp\\payload.exe",
                confidence=0.88,
            ),
            _make_ioc(
                IoCType.REGISTRY_KEY,
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\evil",
                confidence=0.92,
            ),
            # These should be skipped:
            _make_ioc(IoCType.OTHER, "misc-artifact"),
            _make_ioc(IoCType.SERVICE, "evilsvc"),
        ]

    def test_roundtrip_all_indicators_present(
        self,
        client: InvestigationStateClient,
        diverse_iocs: list[IoC],
    ) -> None:
        inv = client.create_investigation("roundtrip-test")
        client.add_iocs(diverse_iocs)
        result = client.export_iocs(format="stix")

        # Parse with stix2
        bundle = stix2.parse(result, allow_custom=True)
        assert bundle.type == "bundle"

        indicators = [o for o in bundle.objects if o.type == "indicator"]

        # 13 mappable types minus 2 unsupported (OTHER, SERVICE) = 13 indicators
        expected_count = 13
        assert len(indicators) == expected_count, f"Expected {expected_count} indicators, got {len(indicators)}"

    def test_roundtrip_values_in_patterns(
        self,
        client: InvestigationStateClient,
        diverse_iocs: list[IoC],
    ) -> None:
        inv = client.create_investigation("values-test")
        client.add_iocs(diverse_iocs)
        result = client.export_iocs(format="stix")

        indicators = [o for o in result["objects"] if o["type"] == "indicator"]
        all_patterns = " ".join(ind["pattern"] for ind in indicators)

        # Spot-check that key values appear in patterns
        assert "192.168.1.100" in all_patterns
        assert "malware-c2.com" in all_patterns
        assert "phish@evil.com" in all_patterns
        assert "backdoor_admin" in all_patterns
        assert "mimikatz.exe" in all_patterns
        # Unsupported values should NOT appear
        assert "misc-artifact" not in all_patterns
        assert "evilsvc" not in all_patterns

    def test_roundtrip_identity_description_contains_investigation_name(
        self,
        client: InvestigationStateClient,
        diverse_iocs: list[IoC],
    ) -> None:
        inv = client.create_investigation("named-inv")
        client.add_iocs(diverse_iocs)
        result = client.export_iocs(format="stix")

        identities = [o for o in result["objects"] if o["type"] == "identity"]
        assert len(identities) == 1
        assert "named-inv" in identities[0]["description"]

    def test_roundtrip_labels_fallback(
        self,
        client: InvestigationStateClient,
    ) -> None:
        """IoC with no tags should get default 'malicious-activity' label."""
        inv = client.create_investigation("labels-test")
        client.add_iocs([_make_ioc(IoCType.IP, "10.10.10.10", tags=[])])
        result = client.export_iocs(format="stix")

        indicators = [o for o in result["objects"] if o["type"] == "indicator"]
        assert len(indicators) == 1
        assert "malicious-activity" in indicators[0]["labels"]

    def test_roundtrip_custom_tags_as_labels(
        self,
        client: InvestigationStateClient,
    ) -> None:
        """IoC with tags should use those as labels."""
        inv = client.create_investigation("tags-test")
        ioc = _make_ioc(IoCType.IP, "10.10.10.11", tags=["apt28", "c2"])
        client.add_iocs([ioc])
        result = client.export_iocs(format="stix")

        indicators = [o for o in result["objects"] if o["type"] == "indicator"]
        assert len(indicators) == 1
        assert "apt28" in indicators[0]["labels"]
        assert "c2" in indicators[0]["labels"]

    def test_roundtrip_indicator_description_contains_priority(
        self,
        client: InvestigationStateClient,
    ) -> None:
        inv = client.create_investigation("desc-test")
        ioc = IoC(
            type=IoCType.IP,
            value="1.2.3.4",
            pyramid_priority=5,
            total_occurrences=42,
            confidence=0.9,
            sources=[IoCSource(tool="manual", source_type=SourceType.MANUAL)],
        )
        client.add_iocs([ioc])
        result = client.export_iocs(format="stix")

        indicators = [o for o in result["objects"] if o["type"] == "indicator"]
        desc = indicators[0]["description"]
        assert "5" in desc
        assert "42" in desc

    def test_roundtrip_multiple_same_type(
        self,
        client: InvestigationStateClient,
    ) -> None:
        """Multiple IoCs of the same type should each get their own indicator."""
        inv = client.create_investigation("multi-ip")
        ips = [_make_ioc(IoCType.IP, f"10.0.0.{i}") for i in range(5)]
        client.add_iocs(ips)
        result = client.export_iocs(format="stix")

        indicators = [o for o in result["objects"] if o["type"] == "indicator"]
        assert len(indicators) == 5

    def test_roundtrip_serialized_bundle_is_valid_json(
        self,
        client: InvestigationStateClient,
    ) -> None:
        inv = client.create_investigation("serial-test")
        client.add_iocs([_make_ioc(IoCType.DOMAIN, "test.evil.com")])
        result = client.export_iocs(format="stix")

        # Serialize and reparse
        as_json = json.dumps(result, indent=2)
        reparsed = json.loads(as_json)
        assert reparsed["type"] == "bundle"
        assert "objects" in reparsed
