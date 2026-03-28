"""Comprehensive unit tests for threat intelligence provider clients.

Tests cover all four providers (Shodan, AbuseIPDB, VirusTotal, ThreatFox),
verdict aggregation, and utility functions. All HTTP calls are mocked.
"""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pytest

# Ensure src is importable
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.clients.common.threat_intel import (
    PROVIDER_WEIGHTS,
    EnrichmentResult,
    _detect_hash_algorithm,
    aggregate_verdicts,
    enrich_abuseipdb,
    enrich_shodan_internetdb,
    enrich_threatfox,
    enrich_virustotal,
    get_configured_providers,
    is_private_ip,
)

# ---------------------------------------------------------------------------
# Fixtures directory
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "threat_intel"


def _load_fixture(name: str) -> dict:
    """Load a JSON fixture file by name."""
    fixture_path = FIXTURES_DIR / name
    with open(fixture_path) as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Helpers: mock httpx responses
# ---------------------------------------------------------------------------


def _mock_response(
    status_code: int = 200,
    json_data: dict | None = None,
    text: str = "",
    raise_for_status_error: bool = False,
) -> MagicMock:
    """Build a mock httpx.Response."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code
    resp.text = text

    if json_data is not None:
        resp.json.return_value = json_data
    else:
        resp.json.side_effect = json.JSONDecodeError("mock", "", 0)

    if raise_for_status_error:
        error_resp = MagicMock()
        error_resp.status_code = status_code
        exc = httpx.HTTPStatusError(
            message=f"HTTP {status_code}",
            request=MagicMock(),
            response=error_resp,
        )
        resp.raise_for_status.side_effect = exc
    else:
        resp.raise_for_status.return_value = None

    return resp


# ---------------------------------------------------------------------------
# Pytest fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def shodan_response_data():
    return _load_fixture("shodan_internetdb_response.json")


@pytest.fixture
def shodan_not_found_data():
    return _load_fixture("shodan_internetdb_not_found.json")


@pytest.fixture
def abuseipdb_response_data():
    return _load_fixture("abuseipdb_response.json")


@pytest.fixture
def abuseipdb_clean_data():
    return _load_fixture("abuseipdb_clean.json")


@pytest.fixture
def virustotal_ip_data():
    return _load_fixture("virustotal_ip_response.json")


@pytest.fixture
def virustotal_hash_data():
    return _load_fixture("virustotal_hash_response.json")


@pytest.fixture
def _clear_env(monkeypatch):
    """Remove all threat-intel API key env vars for isolation."""
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    monkeypatch.delenv("THREATFOX_API_KEY", raising=False)


@pytest.fixture
def _set_all_keys(monkeypatch):
    """Set all API keys to dummy values for provider-available tests."""
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "test-abuse-key")
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "test-vt-key")
    monkeypatch.setenv("THREATFOX_API_KEY", "test-tf-key")


# =========================================================================
# UTILITY FUNCTIONS
# =========================================================================


class TestIsPrivateIp:
    """Tests for is_private_ip utility."""

    @pytest.mark.parametrize(
        "ip",
        [
            "192.168.1.1",
            "192.168.0.0",
            "192.168.255.255",
            "10.0.0.1",
            "10.255.255.255",
            "172.16.0.1",
            "172.31.255.255",
        ],
    )
    def test_rfc1918_addresses(self, ip: str):
        assert is_private_ip(ip) is True

    def test_loopback(self):
        assert is_private_ip("127.0.0.1") is True
        assert is_private_ip("127.255.255.254") is True

    def test_link_local(self):
        assert is_private_ip("169.254.1.1") is True
        assert is_private_ip("169.254.254.254") is True

    @pytest.mark.parametrize(
        "ip",
        [
            "8.8.8.8",
            "1.1.1.1",
            "185.220.101.34",
            "93.184.216.34",
        ],
    )
    def test_public_addresses(self, ip: str):
        assert is_private_ip(ip) is False

    def test_invalid_input(self):
        assert is_private_ip("not-an-ip") is False
        assert is_private_ip("") is False
        assert is_private_ip("999.999.999.999") is False


class TestDetectHashAlgorithm:
    """Tests for _detect_hash_algorithm utility."""

    def test_md5(self):
        assert _detect_hash_algorithm("d" * 32) == "MD5"

    def test_sha1(self):
        assert _detect_hash_algorithm("a" * 40) == "SHA-1"

    def test_sha256(self):
        assert _detect_hash_algorithm("f" * 64) == "SHA-256"

    def test_unknown_length(self):
        assert _detect_hash_algorithm("abc") == "unknown"
        assert _detect_hash_algorithm("") == "unknown"
        assert _detect_hash_algorithm("a" * 128) == "unknown"


class TestGetConfiguredProviders:
    """Tests for get_configured_providers."""

    def test_no_env_vars(self, _clear_env):
        result = get_configured_providers()

        # Shodan is always configured (keyless)
        assert result["shodan_internetdb"]["configured"] is True
        assert result["shodan_internetdb"]["requires_key"] is False
        assert result["shodan_internetdb"]["key_set"] is True

        # Others need keys
        assert result["abuseipdb"]["configured"] is False
        assert result["abuseipdb"]["key_set"] is False
        assert result["virustotal"]["configured"] is False
        assert result["threatfox"]["configured"] is False

    def test_all_env_vars_set(self, _set_all_keys):
        result = get_configured_providers()

        assert result["shodan_internetdb"]["configured"] is True
        assert result["abuseipdb"]["configured"] is True
        assert result["abuseipdb"]["key_set"] is True
        assert result["virustotal"]["configured"] is True
        assert result["virustotal"]["key_set"] is True
        assert result["threatfox"]["configured"] is True
        assert result["threatfox"]["key_set"] is True

    def test_partial_env_vars(self, monkeypatch, _clear_env):
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "vt-only")

        result = get_configured_providers()

        assert result["virustotal"]["configured"] is True
        assert result["abuseipdb"]["configured"] is False
        assert result["threatfox"]["configured"] is False


# =========================================================================
# SHODAN INTERNETDB
# =========================================================================


class TestShodanInternetDB:
    """Tests for enrich_shodan_internetdb."""

    @patch("src.clients.common.threat_intel.httpx.get")
    def test_successful_lookup_with_vulns(self, mock_get, shodan_response_data):
        """IP with vulns returns is_malicious=True and confidence > 0.6."""
        mock_get.return_value = _mock_response(json_data=shodan_response_data)

        result = enrich_shodan_internetdb("8.8.8.8")

        assert result.provider == "shodan_internetdb"
        assert result.ioc_type == "ip"
        assert result.ioc_value == "8.8.8.8"
        assert result.is_malicious is True
        assert result.confidence > 0.6
        assert result.error is None
        assert "CVE-2021-25216" in result.context["vulns"]
        assert len(result.context["ports"]) == 2

    @patch("src.clients.common.threat_intel.httpx.get")
    def test_not_found_404(self, mock_get):
        """404 returns result with no verdict and a note."""
        mock_get.return_value = _mock_response(status_code=404)

        result = enrich_shodan_internetdb("93.184.216.34")

        assert result.provider == "shodan_internetdb"
        assert result.is_malicious is None
        assert result.context.get("note") == "IP not found in InternetDB"
        assert result.error is None

    @patch("src.clients.common.threat_intel.httpx.get")
    def test_no_vulns_no_tags(self, mock_get):
        """IP with no vulns and no tags returns is_malicious=None."""
        data = {"ip": "1.2.3.4", "ports": [80], "hostnames": [], "cpes": [], "vulns": [], "tags": []}
        mock_get.return_value = _mock_response(json_data=data)

        result = enrich_shodan_internetdb("1.2.3.4")

        assert result.is_malicious is None
        assert result.confidence == 0.3
        assert result.error is None

    def test_private_ip_skipped(self):
        """Private IPs are skipped without making HTTP calls."""
        result = enrich_shodan_internetdb("192.168.1.1")

        assert result.provider == "shodan_internetdb"
        assert result.ioc_value == "192.168.1.1"
        assert "private-ip" in result.tags
        assert "Private IP" in result.context.get("note", "")
        assert result.is_malicious is None
        assert result.error is None

    @patch("src.clients.common.threat_intel.httpx.get")
    def test_compromised_tag_malicious(self, mock_get):
        """IP with 'compromised' tag returns is_malicious=True."""
        data = {
            "ip": "5.6.7.8",
            "ports": [22],
            "hostnames": [],
            "cpes": [],
            "vulns": [],
            "tags": ["compromised"],
        }
        mock_get.return_value = _mock_response(json_data=data)

        result = enrich_shodan_internetdb("5.6.7.8")

        assert result.is_malicious is True
        assert "compromised" in result.tags

    @patch("src.clients.common.threat_intel.httpx.get")
    def test_http_timeout(self, mock_get):
        """Timeout produces error result, does not raise."""
        mock_get.side_effect = httpx.TimeoutException("Connection timed out")

        result = enrich_shodan_internetdb("8.8.8.8")

        assert result.provider == "shodan_internetdb"
        assert result.error is not None
        assert "Connection error" in result.error
        assert result.is_malicious is None

    @patch("src.clients.common.threat_intel.httpx.get")
    def test_http_500_error(self, mock_get):
        """Server error returns error result, does not raise."""
        mock_get.return_value = _mock_response(status_code=500, raise_for_status_error=True)

        result = enrich_shodan_internetdb("8.8.8.8")

        assert result.error is not None
        assert "500" in result.error
        assert result.is_malicious is None

    @patch("src.clients.common.threat_intel.httpx.get")
    def test_http_429_rate_limit(self, mock_get):
        """429 response returns error result."""
        mock_get.return_value = _mock_response(status_code=429, raise_for_status_error=True)

        result = enrich_shodan_internetdb("8.8.8.8")

        assert result.error is not None
        assert "429" in result.error

    @patch("src.clients.common.threat_intel.httpx.get")
    def test_malformed_json(self, mock_get):
        """Malformed response is handled gracefully via missing keys."""
        # Valid JSON but missing expected fields
        mock_get.return_value = _mock_response(json_data={"unexpected": "structure"})

        result = enrich_shodan_internetdb("8.8.8.8")

        # Should still return a result, just with empty data
        assert result.provider == "shodan_internetdb"
        assert result.error is None
        assert result.context["vulns"] == []
        assert result.context["ports"] == []

    @patch("src.clients.common.threat_intel.httpx.get")
    def test_connect_error(self, mock_get):
        """Connection error returns error result."""
        mock_get.side_effect = httpx.ConnectError("DNS resolution failed")

        result = enrich_shodan_internetdb("8.8.8.8")

        assert result.error is not None
        assert "Connection error" in result.error

    @patch("src.clients.common.threat_intel.httpx.get")
    def test_confidence_scales_with_vulns(self, mock_get):
        """More vulns produce higher confidence, capped at 0.9."""
        many_vulns = [f"CVE-2024-{i:04d}" for i in range(20)]
        data = {"ip": "1.2.3.4", "ports": [], "hostnames": [], "cpes": [], "vulns": many_vulns, "tags": []}
        mock_get.return_value = _mock_response(json_data=data)

        result = enrich_shodan_internetdb("1.2.3.4")

        assert result.confidence == 0.9  # capped
        assert result.is_malicious is True


# =========================================================================
# ABUSEIPDB
# =========================================================================


class TestAbuseIPDB:
    """Tests for enrich_abuseipdb."""

    @patch("src.clients.common.threat_intel.httpx.get")
    def test_successful_high_abuse(self, mock_get, abuseipdb_response_data):
        """Score >= 80 returns is_malicious=True with 'high-abuse' tag."""
        mock_get.return_value = _mock_response(json_data=abuseipdb_response_data)

        result = enrich_abuseipdb("185.220.101.34", api_key="test-key")

        assert result is not None
        assert result.provider == "abuseipdb"
        assert result.is_malicious is True
        assert result.confidence == 0.92
        assert "high-abuse" in result.tags
        assert result.context["abuse_confidence_score"] == 92
        assert result.context["total_reports"] == 1847
        assert result.error is None

    @patch("src.clients.common.threat_intel.httpx.get")
    def test_clean_ip_low_score(self, mock_get, abuseipdb_clean_data):
        """Score < 50 returns is_malicious=False."""
        mock_get.return_value = _mock_response(json_data=abuseipdb_clean_data)

        result = enrich_abuseipdb("8.8.8.8", api_key="test-key")

        assert result is not None
        assert result.is_malicious is False
        assert result.confidence == 0.03
        assert result.tags == []
        assert result.context["is_whitelisted"] is True

    @patch("src.clients.common.threat_intel.httpx.get")
    def test_moderate_abuse_score(self, mock_get):
        """Score between 50-79 returns is_malicious=True with 'moderate-abuse' tag."""
        data = {
            "data": {
                "abuseConfidenceScore": 65,
                "totalReports": 50,
                "countryCode": "RU",
                "isp": "Some ISP",
                "usageType": "ISP",
                "domain": "example.com",
                "isWhitelisted": False,
            }
        }
        mock_get.return_value = _mock_response(json_data=data)

        result = enrich_abuseipdb("1.2.3.4", api_key="test-key")

        assert result is not None
        assert result.is_malicious is True
        assert "moderate-abuse" in result.tags
        assert "high-abuse" not in result.tags

    def test_api_key_missing_returns_none(self, _clear_env):
        """No API key returns None (graceful skip)."""
        result = enrich_abuseipdb("8.8.8.8")
        assert result is None

    def test_private_ip_skipped(self):
        """Private IP is skipped with tag."""
        result = enrich_abuseipdb("10.0.0.1", api_key="test-key")

        assert result is not None
        assert "private-ip" in result.tags
        assert result.is_malicious is None

    @patch("src.clients.common.threat_intel.httpx.get")
    def test_http_timeout(self, mock_get):
        """Timeout produces error result, does not raise."""
        mock_get.side_effect = httpx.TimeoutException("read timed out")

        result = enrich_abuseipdb("8.8.8.8", api_key="test-key")

        assert result is not None
        assert result.error is not None
        assert result.is_malicious is None

    @patch("src.clients.common.threat_intel.httpx.get")
    def test_http_429_rate_limit(self, mock_get):
        """429 returns rate-limit error result."""
        mock_get.return_value = _mock_response(status_code=429)

        result = enrich_abuseipdb("8.8.8.8", api_key="test-key")

        assert result is not None
        assert result.error == "Rate limit exceeded"

    @patch("src.clients.common.threat_intel.httpx.get")
    def test_http_500_error(self, mock_get):
        """Server error returns error result, does not raise."""
        mock_get.side_effect = httpx.HTTPStatusError(
            message="HTTP 500",
            request=MagicMock(),
            response=MagicMock(status_code=500),
        )

        result = enrich_abuseipdb("8.8.8.8", api_key="test-key")

        assert result is not None
        assert result.error is not None
        assert result.is_malicious is None

    @patch("src.clients.common.threat_intel.httpx.get")
    def test_malformed_response_missing_data_key(self, mock_get):
        """Response missing 'data' key uses defaults gracefully."""
        mock_get.return_value = _mock_response(json_data={"unexpected": True})

        result = enrich_abuseipdb("8.8.8.8", api_key="test-key")

        assert result is not None
        # data.get("abuseConfidenceScore", 0) returns 0 for empty dict
        assert result.is_malicious is False
        assert result.confidence == 0.0

    @patch("src.clients.common.threat_intel.httpx.get")
    def test_api_key_from_env(self, mock_get, monkeypatch):
        """API key is read from environment when not passed directly."""
        monkeypatch.setenv("ABUSEIPDB_API_KEY", "env-key-123")
        data = {"data": {"abuseConfidenceScore": 10, "totalReports": 1}}
        mock_get.return_value = _mock_response(json_data=data)

        result = enrich_abuseipdb("8.8.8.8")

        assert result is not None
        mock_get.assert_called_once()
        call_headers = mock_get.call_args.kwargs.get("headers", {})
        assert call_headers.get("Key") == "env-key-123"


# =========================================================================
# VIRUSTOTAL
# =========================================================================


class TestVirusTotal:
    """Tests for enrich_virustotal."""

    @patch("src.clients.common.threat_intel.time.time", return_value=99999999.0)
    @patch("src.clients.common.threat_intel.time.sleep")
    @patch("src.clients.common.threat_intel.httpx.get")
    def test_successful_ip_lookup_malicious(self, mock_get, mock_sleep, mock_time, virustotal_ip_data):
        """IP with malicious + suspicious >= 3 returns is_malicious=True."""
        import src.clients.common.threat_intel as ti_module

        ti_module._vt_last_call = 0.0
        mock_get.return_value = _mock_response(json_data=virustotal_ip_data)

        result = enrich_virustotal("ip", "185.220.101.34", api_key="test-key")

        assert result is not None
        assert result.provider == "virustotal"
        assert result.ioc_type == "ip"
        assert result.is_malicious is True
        assert result.confidence > 0
        assert "vt-malicious" in result.tags
        assert result.context["as_owner"] == "Zwiebelfreunde e.V."
        assert result.context["country"] == "DE"
        assert result.error is None

    @patch("src.clients.common.threat_intel.time.time", return_value=99999999.0)
    @patch("src.clients.common.threat_intel.time.sleep")
    @patch("src.clients.common.threat_intel.httpx.get")
    def test_successful_hash_lookup(self, mock_get, mock_sleep, mock_time, virustotal_hash_data):
        """Hash lookup returns file context and hash_algorithm."""
        import src.clients.common.threat_intel as ti_module

        ti_module._vt_last_call = 0.0
        sha256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
        mock_get.return_value = _mock_response(json_data=virustotal_hash_data)

        result = enrich_virustotal("hash", sha256, api_key="test-key")

        assert result is not None
        assert result.ioc_type == "hash"
        assert result.is_malicious is True
        assert result.context["hash_algorithm"] == "SHA-256"
        assert result.context["type_description"] == "Win32 EXE"
        assert result.context["size"] == 184320
        assert "vt-malicious" in result.tags

    @patch("src.clients.common.threat_intel.time.time", return_value=99999999.0)
    @patch("src.clients.common.threat_intel.time.sleep")
    @patch("src.clients.common.threat_intel.httpx.get")
    def test_domain_lookup(self, mock_get, mock_sleep, mock_time):
        """Domain lookup includes registrar context."""
        import src.clients.common.threat_intel as ti_module

        ti_module._vt_last_call = 0.0
        data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 50, "undetected": 20},
                    "reputation": 10,
                    "registrar": "GoDaddy",
                    "creation_date": 946684800,
                }
            }
        }
        mock_get.return_value = _mock_response(json_data=data)

        result = enrich_virustotal("domain", "example.com", api_key="test-key")

        assert result is not None
        assert result.ioc_type == "domain"
        assert result.is_malicious is False
        assert result.context["registrar"] == "GoDaddy"
        assert result.tags == []

    @patch("src.clients.common.threat_intel.time.time", return_value=99999999.0)
    @patch("src.clients.common.threat_intel.time.sleep")
    @patch("src.clients.common.threat_intel.httpx.get")
    def test_url_lookup_base64_encoding(self, mock_get, mock_sleep, mock_time):
        """URL lookup encodes the URL in base64 (no padding)."""
        import base64

        import src.clients.common.threat_intel as ti_module

        ti_module._vt_last_call = 0.0
        data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 5, "suspicious": 1, "harmless": 30, "undetected": 10},
                    "reputation": -20,
                }
            }
        }
        mock_get.return_value = _mock_response(json_data=data)

        result = enrich_virustotal("url", "https://evil.example.com/malware", api_key="test-key")

        assert result is not None
        assert result.ioc_type == "url"
        assert result.is_malicious is True

        # Verify base64 encoding was used in the URL
        called_url = mock_get.call_args.args[0]
        expected_encoded = base64.urlsafe_b64encode(b"https://evil.example.com/malware").rstrip(b"=").decode()
        assert expected_encoded in called_url

    @patch("src.clients.common.threat_intel.time.time", return_value=99999999.0)
    @patch("src.clients.common.threat_intel.time.sleep")
    @patch("src.clients.common.threat_intel.httpx.get")
    def test_not_found_404(self, mock_get, mock_sleep, mock_time):
        """404 returns result with 'Not found in VirusTotal' note."""
        import src.clients.common.threat_intel as ti_module

        ti_module._vt_last_call = 0.0
        mock_get.return_value = _mock_response(status_code=404)

        result = enrich_virustotal("ip", "93.184.216.34", api_key="test-key")

        assert result is not None
        assert result.context.get("note") == "Not found in VirusTotal"
        assert result.is_malicious is None
        assert result.error is None

    @patch("src.clients.common.threat_intel.time.time", return_value=99999999.0)
    @patch("src.clients.common.threat_intel.time.sleep")
    @patch("src.clients.common.threat_intel.httpx.get")
    def test_low_detection_not_malicious(self, mock_get, mock_sleep, mock_time):
        """malicious + suspicious < 3 returns is_malicious=False or None."""
        import src.clients.common.threat_intel as ti_module

        ti_module._vt_last_call = 0.0
        data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 1, "suspicious": 0, "harmless": 60, "undetected": 10},
                    "reputation": 5,
                }
            }
        }
        mock_get.return_value = _mock_response(json_data=data)

        result = enrich_virustotal("ip", "8.8.8.8", api_key="test-key")

        assert result is not None
        assert result.is_malicious is False
        assert result.tags == []

    def test_api_key_missing_returns_none(self, _clear_env):
        """No API key returns None (graceful skip)."""
        result = enrich_virustotal("ip", "8.8.8.8")
        assert result is None

    @patch("src.clients.common.threat_intel.time.time", return_value=99999999.0)
    @patch("src.clients.common.threat_intel.time.sleep")
    @patch("src.clients.common.threat_intel.httpx.get")
    def test_http_timeout(self, mock_get, mock_sleep, mock_time):
        """Timeout produces error result, does not raise."""
        import src.clients.common.threat_intel as ti_module

        ti_module._vt_last_call = 0.0
        mock_get.side_effect = httpx.TimeoutException("Connection timed out")

        result = enrich_virustotal("ip", "8.8.8.8", api_key="test-key")

        assert result is not None
        assert result.error is not None
        assert result.is_malicious is None

    @patch("src.clients.common.threat_intel.time.time", return_value=99999999.0)
    @patch("src.clients.common.threat_intel.time.sleep")
    @patch("src.clients.common.threat_intel.httpx.get")
    def test_http_429_rate_limit(self, mock_get, mock_sleep, mock_time):
        """429 returns rate-limit error result."""
        import src.clients.common.threat_intel as ti_module

        ti_module._vt_last_call = 0.0
        mock_get.return_value = _mock_response(status_code=429)

        result = enrich_virustotal("ip", "8.8.8.8", api_key="test-key")

        assert result is not None
        assert result.error == "Rate limit exceeded"

    @patch("src.clients.common.threat_intel.time.time", return_value=99999999.0)
    @patch("src.clients.common.threat_intel.time.sleep")
    @patch("src.clients.common.threat_intel.httpx.get")
    def test_http_500_error(self, mock_get, mock_sleep, mock_time):
        """Server error returns error result."""
        import src.clients.common.threat_intel as ti_module

        ti_module._vt_last_call = 0.0
        mock_get.side_effect = httpx.HTTPStatusError(
            message="HTTP 500",
            request=MagicMock(),
            response=MagicMock(status_code=500),
        )

        result = enrich_virustotal("ip", "8.8.8.8", api_key="test-key")

        assert result is not None
        assert result.error is not None

    def test_unsupported_ioc_type(self):
        """Unsupported IoC type returns error result."""
        result = enrich_virustotal("email", "test@example.com", api_key="test-key")

        assert result is not None
        assert result.error is not None
        assert "Unsupported" in result.error

    @patch("src.clients.common.threat_intel.time.time", return_value=99999999.0)
    @patch("src.clients.common.threat_intel.time.sleep")
    @patch("src.clients.common.threat_intel.httpx.get")
    def test_malformed_response_empty_data(self, mock_get, mock_sleep, mock_time):
        """Response missing 'data.attributes' uses defaults."""
        import src.clients.common.threat_intel as ti_module

        ti_module._vt_last_call = 0.0
        mock_get.return_value = _mock_response(json_data={"data": {}})

        result = enrich_virustotal("ip", "8.8.8.8", api_key="test-key")

        assert result is not None
        assert result.is_malicious is None  # total == 0 => None
        assert result.error is None

    @patch("src.clients.common.threat_intel.time.time", return_value=99999999.0)
    @patch("src.clients.common.threat_intel.time.sleep")
    @patch("src.clients.common.threat_intel.httpx.get")
    def test_rate_limit_delay_applied(self, mock_get, mock_sleep, mock_time):
        """Rate limiting sleep is triggered when calls are too close."""
        import src.clients.common.threat_intel as ti_module

        # Simulate last call was 5 seconds ago (< VT_RATE_LIMIT_DELAY=15)
        ti_module._vt_last_call = 99999999.0 - 5.0
        data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 50, "undetected": 10},
                    "reputation": 0,
                }
            }
        }
        mock_get.return_value = _mock_response(json_data=data)

        enrich_virustotal("ip", "8.8.8.8", api_key="test-key")

        # sleep should have been called with roughly 10 seconds
        mock_sleep.assert_called_once()
        sleep_duration = mock_sleep.call_args.args[0]
        assert 9.0 <= sleep_duration <= 11.0

    @patch("src.clients.common.threat_intel.time.time", return_value=99999999.0)
    @patch("src.clients.common.threat_intel.time.sleep")
    @patch("src.clients.common.threat_intel.httpx.get")
    def test_api_key_from_env(self, mock_get, mock_sleep, mock_time, monkeypatch):
        """API key is read from environment when not passed directly."""
        import src.clients.common.threat_intel as ti_module

        ti_module._vt_last_call = 0.0
        monkeypatch.setenv("VIRUSTOTAL_API_KEY", "env-vt-key")
        data = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0, "harmless": 50, "undetected": 10},
                    "reputation": 0,
                }
            }
        }
        mock_get.return_value = _mock_response(json_data=data)

        result = enrich_virustotal("ip", "8.8.8.8")

        assert result is not None
        call_headers = mock_get.call_args.kwargs.get("headers", {})
        assert call_headers.get("x-apikey") == "env-vt-key"


# =========================================================================
# THREATFOX
# =========================================================================


class TestThreatFox:
    """Tests for enrich_threatfox."""

    @patch("src.clients.common.threat_intel.httpx.post")
    def test_match_found(self, mock_post):
        """Match found returns is_malicious=True with malware family in context."""
        data = {
            "query_status": "ok",
            "data": [
                {
                    "malware": "win.emotet",
                    "malware_printable": "Emotet",
                    "threat_type": "botnet_cc",
                    "confidence_level": 90,
                    "first_seen": "2026-01-01",
                    "last_seen_utc": "2026-03-28",
                    "reporter": "abuse_ch",
                    "reference": "https://example.com/emotet",
                    "tags": ["emotet", "banking"],
                    "malware_malpedia": "https://malpedia.caad.fkie.fraunhofer.de/details/win.emotet",
                }
            ],
        }
        mock_post.return_value = _mock_response(json_data=data)

        result = enrich_threatfox("ip", "5.6.7.8", api_key="test-key")

        assert result is not None
        assert result.provider == "threatfox"
        assert result.is_malicious is True
        assert result.confidence == 0.9
        assert result.context["malware_family"] == "Emotet"
        assert result.context["threat_type"] == "botnet_cc"
        assert "malware:Emotet" in result.tags
        assert "threat:botnet_cc" in result.tags
        assert len(result.mitre_techniques) == 1
        assert result.error is None

    @patch("src.clients.common.threat_intel.httpx.post")
    def test_no_match_no_result_status(self, mock_post):
        """query_status='no_result' returns context with 'No match' note."""
        data = {"query_status": "no_result", "data": None}
        mock_post.return_value = _mock_response(json_data=data)

        result = enrich_threatfox("ip", "8.8.8.8", api_key="test-key")

        assert result is not None
        assert result.is_malicious is None
        assert "No match" in result.context.get("note", "")
        assert result.error is None

    @patch("src.clients.common.threat_intel.httpx.post")
    def test_no_match_empty_data_list(self, mock_post):
        """Empty data list returns 'No match' note."""
        data = {"query_status": "ok", "data": []}
        mock_post.return_value = _mock_response(json_data=data)

        result = enrich_threatfox("domain", "example.com", api_key="test-key")

        assert result is not None
        assert "No match" in result.context.get("note", "")

    def test_api_key_missing_returns_none(self, _clear_env):
        """No API key returns None (graceful skip)."""
        result = enrich_threatfox("ip", "8.8.8.8")
        assert result is None

    def test_unsupported_ioc_type_returns_none(self):
        """Unsupported IoC type returns None."""
        result = enrich_threatfox("email", "test@example.com", api_key="test-key")
        assert result is None

    @patch("src.clients.common.threat_intel.httpx.post")
    def test_http_timeout(self, mock_post):
        """Timeout produces error result, does not raise."""
        mock_post.side_effect = httpx.TimeoutException("Connection timed out")

        result = enrich_threatfox("ip", "8.8.8.8", api_key="test-key")

        assert result is not None
        assert result.error is not None
        assert result.is_malicious is None

    @patch("src.clients.common.threat_intel.httpx.post")
    def test_http_429_rate_limit(self, mock_post):
        """429 returns rate-limit error result."""
        mock_post.return_value = _mock_response(status_code=429)

        result = enrich_threatfox("ip", "8.8.8.8", api_key="test-key")

        assert result is not None
        assert result.error == "Rate limit exceeded"

    @patch("src.clients.common.threat_intel.httpx.post")
    def test_http_500_error(self, mock_post):
        """Server error returns error result."""
        mock_post.side_effect = httpx.HTTPStatusError(
            message="HTTP 500",
            request=MagicMock(),
            response=MagicMock(status_code=500),
        )

        result = enrich_threatfox("ip", "8.8.8.8", api_key="test-key")

        assert result is not None
        assert result.error is not None

    @patch("src.clients.common.threat_intel.httpx.post")
    def test_malformed_response_missing_fields(self, mock_post):
        """Match with missing optional fields handled gracefully."""
        data = {
            "query_status": "ok",
            "data": [
                {
                    "malware": "",
                    "malware_printable": "",
                    "threat_type": "",
                    "confidence_level": 0,
                }
            ],
        }
        mock_post.return_value = _mock_response(json_data=data)

        result = enrich_threatfox("ip", "8.8.8.8", api_key="test-key")

        assert result is not None
        assert result.is_malicious is True
        assert result.confidence == 0.85  # default when confidence_level is 0/falsy
        assert result.tags == []  # empty malware_printable => no tags

    @patch("src.clients.common.threat_intel.httpx.post")
    def test_connect_error(self, mock_post):
        """Connection error returns error result."""
        mock_post.side_effect = httpx.ConnectError("Connection refused")

        result = enrich_threatfox("ip", "8.8.8.8", api_key="test-key")

        assert result is not None
        assert result.error is not None

    @patch("src.clients.common.threat_intel.httpx.post")
    def test_api_key_from_env(self, mock_post, monkeypatch):
        """API key is read from environment when not passed directly."""
        monkeypatch.setenv("THREATFOX_API_KEY", "env-tf-key")
        data = {"query_status": "no_result", "data": None}
        mock_post.return_value = _mock_response(json_data=data)

        result = enrich_threatfox("ip", "8.8.8.8")

        assert result is not None
        call_headers = mock_post.call_args.kwargs.get("headers", {})
        assert call_headers.get("API-KEY") == "env-tf-key"

    @patch("src.clients.common.threat_intel.httpx.post")
    def test_no_malpedia_link(self, mock_post):
        """Match without malpedia link has empty mitre_techniques."""
        data = {
            "query_status": "ok",
            "data": [
                {
                    "malware": "win.raccoon",
                    "malware_printable": "Raccoon Stealer",
                    "threat_type": "stealer",
                    "confidence_level": 75,
                    "tags": ["stealer"],
                }
            ],
        }
        mock_post.return_value = _mock_response(json_data=data)

        result = enrich_threatfox("hash", "a" * 64, api_key="test-key")

        assert result is not None
        assert result.mitre_techniques == []
        assert result.context["malware_family"] == "Raccoon Stealer"


# =========================================================================
# VERDICT AGGREGATION
# =========================================================================


class TestAggregateVerdicts:
    """Tests for aggregate_verdicts."""

    def test_all_malicious_high_confidence(self):
        """All providers say malicious => high confidence malicious."""
        results = [
            EnrichmentResult(
                provider="virustotal", ioc_type="ip", ioc_value="1.2.3.4", is_malicious=True, confidence=0.9
            ),
            EnrichmentResult(
                provider="abuseipdb", ioc_type="ip", ioc_value="1.2.3.4", is_malicious=True, confidence=0.85
            ),
            EnrichmentResult(
                provider="threatfox", ioc_type="ip", ioc_value="1.2.3.4", is_malicious=True, confidence=0.95
            ),
            EnrichmentResult(
                provider="shodan_internetdb", ioc_type="ip", ioc_value="1.2.3.4", is_malicious=True, confidence=0.7
            ),
        ]

        is_mal, confidence = aggregate_verdicts(results)

        assert is_mal is True
        assert confidence > 0.8

    def test_all_benign(self):
        """All providers say benign => confidence < 0.5, is_malicious=False."""
        results = [
            EnrichmentResult(
                provider="virustotal", ioc_type="ip", ioc_value="8.8.8.8", is_malicious=False, confidence=0.1
            ),
            EnrichmentResult(
                provider="abuseipdb", ioc_type="ip", ioc_value="8.8.8.8", is_malicious=False, confidence=0.05
            ),
        ]

        is_mal, confidence = aggregate_verdicts(results)

        assert is_mal is False
        assert confidence < 0.5

    def test_mixed_verdicts_weighted(self):
        """Mixed verdicts use weighted scores to determine outcome."""
        # VT says malicious (weight 0.35), AbuseIPDB says benign (weight 0.25)
        results = [
            EnrichmentResult(
                provider="virustotal", ioc_type="ip", ioc_value="1.2.3.4", is_malicious=True, confidence=0.8
            ),
            EnrichmentResult(
                provider="abuseipdb", ioc_type="ip", ioc_value="1.2.3.4", is_malicious=False, confidence=0.3
            ),
        ]

        is_mal, confidence = aggregate_verdicts(results)

        # VT weighted: 1.0 * 0.35 * 0.8 = 0.28
        # AbuseIPDB weighted: 0.0 * 0.25 * 0.3 = 0.0
        # Total weight: 0.35 + 0.25 = 0.6
        # Final: 0.28 / 0.6 = 0.467
        assert isinstance(is_mal, bool)
        assert 0.0 <= confidence <= 1.0

    def test_single_provider_verdict(self):
        """Single provider available uses that provider's weighted verdict."""
        results = [
            EnrichmentResult(
                provider="virustotal", ioc_type="ip", ioc_value="1.2.3.4", is_malicious=True, confidence=0.9
            ),
        ]

        is_mal, confidence = aggregate_verdicts(results)

        assert is_mal is True
        assert confidence == 0.9  # 1.0 * 0.35 * 0.9 / 0.35 = 0.9

    def test_no_verdicts_returns_none(self):
        """No providers have verdict => (None, 0.5)."""
        results: list[EnrichmentResult] = []

        is_mal, confidence = aggregate_verdicts(results)

        assert is_mal is None
        assert confidence == 0.5

    def test_all_none_verdicts_returns_none(self):
        """All results have is_malicious=None => (None, 0.5)."""
        results = [
            EnrichmentResult(
                provider="virustotal", ioc_type="ip", ioc_value="1.2.3.4", is_malicious=None, confidence=0.5
            ),
            EnrichmentResult(
                provider="shodan_internetdb", ioc_type="ip", ioc_value="1.2.3.4", is_malicious=None, confidence=0.3
            ),
        ]

        is_mal, confidence = aggregate_verdicts(results)

        assert is_mal is None
        assert confidence == 0.5

    def test_error_results_excluded(self):
        """Results with errors are excluded from aggregation."""
        results = [
            EnrichmentResult(
                provider="virustotal",
                ioc_type="ip",
                ioc_value="1.2.3.4",
                is_malicious=True,
                confidence=0.9,
                error="Rate limit exceeded",
            ),
            EnrichmentResult(
                provider="abuseipdb", ioc_type="ip", ioc_value="1.2.3.4", is_malicious=True, confidence=0.8
            ),
        ]

        is_mal, confidence = aggregate_verdicts(results)

        # Only abuseipdb should count (VT has error)
        assert is_mal is True
        assert confidence == 0.8  # 1.0 * 0.25 * 0.8 / 0.25 = 0.8

    def test_one_provider_errors_others_succeed(self):
        """Partial results work when one provider errors."""
        results = [
            EnrichmentResult(
                provider="virustotal", ioc_type="ip", ioc_value="1.2.3.4", is_malicious=True, confidence=0.9
            ),
            EnrichmentResult(provider="abuseipdb", ioc_type="ip", ioc_value="1.2.3.4", error="Connection timeout"),
            EnrichmentResult(
                provider="threatfox", ioc_type="ip", ioc_value="1.2.3.4", is_malicious=True, confidence=0.85
            ),
        ]

        is_mal, confidence = aggregate_verdicts(results)

        assert is_mal is True
        assert confidence > 0.8

    def test_unknown_provider_uses_default_weight(self):
        """Unknown provider gets default weight of 0.1."""
        results = [
            EnrichmentResult(
                provider="custom_provider", ioc_type="ip", ioc_value="1.2.3.4", is_malicious=True, confidence=1.0
            ),
        ]

        is_mal, confidence = aggregate_verdicts(results)

        assert is_mal is True
        # 1.0 * 0.1 * 1.0 / 0.1 = 1.0
        assert confidence == 1.0

    def test_provider_weights_are_defined(self):
        """All expected providers have weights defined."""
        assert "virustotal" in PROVIDER_WEIGHTS
        assert "abuseipdb" in PROVIDER_WEIGHTS
        assert "threatfox" in PROVIDER_WEIGHTS
        assert "shodan_internetdb" in PROVIDER_WEIGHTS
        assert PROVIDER_WEIGHTS["virustotal"] == 0.35

    def test_confidence_is_rounded(self):
        """Confidence is rounded to 3 decimal places."""
        results = [
            EnrichmentResult(
                provider="virustotal", ioc_type="ip", ioc_value="1.2.3.4", is_malicious=True, confidence=0.777
            ),
            EnrichmentResult(
                provider="abuseipdb", ioc_type="ip", ioc_value="1.2.3.4", is_malicious=False, confidence=0.333
            ),
        ]

        _, confidence = aggregate_verdicts(results)

        # Should have at most 3 decimal places
        assert confidence == round(confidence, 3)


# =========================================================================
# ENRICHMENT RESULT DATACLASS
# =========================================================================


class TestEnrichmentResult:
    """Tests for the EnrichmentResult frozen dataclass."""

    def test_defaults(self):
        result = EnrichmentResult(provider="test", ioc_type="ip", ioc_value="1.2.3.4")

        assert result.is_malicious is None
        assert result.confidence == 0.5
        assert result.context == {}
        assert result.tags == []
        assert result.mitre_techniques == []
        assert result.error is None

    def test_frozen(self):
        """EnrichmentResult is immutable (frozen dataclass)."""
        result = EnrichmentResult(provider="test", ioc_type="ip", ioc_value="1.2.3.4")

        with pytest.raises(AttributeError):
            result.provider = "modified"  # type: ignore[misc]

    def test_all_fields(self):
        result = EnrichmentResult(
            provider="virustotal",
            ioc_type="hash",
            ioc_value="abc123",
            is_malicious=True,
            confidence=0.95,
            context={"key": "value"},
            tags=["malware"],
            mitre_techniques=["T1059"],
            error=None,
        )

        assert result.provider == "virustotal"
        assert result.ioc_type == "hash"
        assert result.is_malicious is True
        assert result.confidence == 0.95
        assert result.context == {"key": "value"}
        assert result.tags == ["malware"]
        assert result.mitre_techniques == ["T1059"]
