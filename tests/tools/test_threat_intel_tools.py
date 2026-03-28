"""Tests for ThreatIntelTools MCP tool layer.

Covers _enrich_iocs, _lookup_ioc, _get_enrichment_status — the orchestration
logic between provider clients and investigation state.
"""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from src.clients.common.threat_intel import EnrichmentResult
from src.storage.config import StorageConfig, set_config
from src.storage.investigation_state import InvestigationStateClient
from src.storage.models import (
    IoC,
    IoCType,
    SourceType,
)
from src.tools.threat_intel import ThreatIntelTools

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_config(tmp_path: Path) -> StorageConfig:
    cfg = StorageConfig(base_path=tmp_path / ".crowdsentinel")
    set_config(cfg)
    return cfg


@pytest.fixture
def client(tmp_config: StorageConfig) -> InvestigationStateClient:
    c = InvestigationStateClient()
    c.create_investigation("Test Investigation", description="for TI tool tests")
    return c


@pytest.fixture
def tools() -> ThreatIntelTools:
    return ThreatIntelTools()


def _add_iocs(client: InvestigationStateClient, iocs: list[IoC]):
    """Helper to inject IoCs into the active investigation."""
    for ioc in iocs:
        client.active_investigation.iocs.add_ioc(ioc)


def _make_ioc(ioc_type: str, value: str, priority: int = 3) -> IoC:
    return IoC(type=IoCType(ioc_type), value=value, pyramid_priority=priority)


def _mock_enrich(ioc_type, ioc_value, providers=None):
    """Return a single Shodan result for any IP, empty for others."""
    if ioc_type == "ip":
        return [
            EnrichmentResult(
                provider="shodan_internetdb",
                ioc_type="ip",
                ioc_value=ioc_value,
                is_malicious=True,
                confidence=0.75,
                context={"ports": [22, 80], "vulns": ["CVE-2024-1234"]},
                tags=["compromised"],
            )
        ]
    return []


# ---------------------------------------------------------------------------
# _enrich_iocs tests
# ---------------------------------------------------------------------------


class TestEnrichIocs:
    def test_no_investigation_returns_error(self, tools, tmp_config):
        # No investigation created — use a fresh client
        import src.storage.auto_capture as ac

        ac._client = InvestigationStateClient()
        result = tools._enrich_iocs(None, None, 1, None, 20)
        assert "error" in result

    @patch("src.tools.threat_intel.enrich_single_ioc", side_effect=_mock_enrich)
    @patch("src.tools.threat_intel.get_investigation_client")
    def test_enriches_ip_iocs(self, mock_get_client, mock_enrich, tools, client):
        mock_get_client.return_value = client
        _add_iocs(client, [_make_ioc("ip", "8.8.8.8", 4)])

        result = tools._enrich_iocs(None, None, 1, None, 20)

        assert result["enriched_count"] == 1
        assert result["enriched_iocs"][0]["verdict"] == "malicious"
        assert result["enriched_iocs"][0]["confidence"] == 0.75
        assert "investigation_id" in result
        assert "workflow_hint" in result

    @patch("src.tools.threat_intel.enrich_single_ioc", side_effect=_mock_enrich)
    @patch("src.tools.threat_intel.get_investigation_client")
    def test_empty_after_type_filter(self, mock_get_client, mock_enrich, tools, client):
        mock_get_client.return_value = client
        _add_iocs(client, [_make_ioc("ip", "1.2.3.4", 3)])

        result = tools._enrich_iocs(None, ["hash"], 1, None, 20)

        assert result["enriched_count"] == 0
        assert "message" in result

    @patch("src.tools.threat_intel.enrich_single_ioc", side_effect=_mock_enrich)
    @patch("src.tools.threat_intel.get_investigation_client")
    def test_priority_filter(self, mock_get_client, mock_enrich, tools, client):
        mock_get_client.return_value = client
        _add_iocs(
            client,
            [
                _make_ioc("ip", "1.1.1.1", 2),
                _make_ioc("ip", "2.2.2.2", 5),
            ],
        )

        result = tools._enrich_iocs(None, None, 4, None, 20)

        assert result["enriched_count"] == 1
        assert result["enriched_iocs"][0]["value"] == "2.2.2.2"

    @patch("src.tools.threat_intel.enrich_single_ioc", side_effect=_mock_enrich)
    @patch("src.tools.threat_intel.get_investigation_client")
    def test_max_iocs_limit(self, mock_get_client, mock_enrich, tools, client):
        mock_get_client.return_value = client
        _add_iocs(client, [_make_ioc("ip", f"10.0.0.{i}", 3) for i in range(50)])

        result = tools._enrich_iocs(None, None, 1, None, 5)

        assert result["enriched_count"] == 5

    @patch("src.tools.threat_intel.enrich_single_ioc", side_effect=_mock_enrich)
    @patch("src.tools.threat_intel.get_investigation_client")
    def test_hard_cap_200(self, mock_get_client, mock_enrich, tools, client):
        mock_get_client.return_value = client
        _add_iocs(client, [_make_ioc("ip", f"10.0.{i // 256}.{i % 256}", 3) for i in range(250)])

        result = tools._enrich_iocs(None, None, 1, None, 999)

        assert result["enriched_count"] == 200

    @patch("src.tools.threat_intel.enrich_single_ioc", return_value=[])
    @patch("src.tools.threat_intel.get_investigation_client")
    def test_unsupported_type_no_providers(self, mock_get_client, mock_enrich, tools, client):
        mock_get_client.return_value = client
        _add_iocs(client, [_make_ioc("registry_key", r"HKLM\Software\Evil", 5)])

        result = tools._enrich_iocs(None, None, 1, None, 20)

        assert result["enriched_count"] == 1
        assert result["verdicts"]["unknown"] == 1

    @patch("src.tools.threat_intel.enrich_single_ioc", side_effect=_mock_enrich)
    @patch("src.tools.threat_intel.get_investigation_client")
    def test_provider_stats_tracked(self, mock_get_client, mock_enrich, tools, client):
        mock_get_client.return_value = client
        _add_iocs(client, [_make_ioc("ip", "8.8.4.4", 3)])

        result = tools._enrich_iocs(None, None, 1, None, 20)

        assert "shodan_internetdb" in result["provider_stats"]
        assert result["provider_stats"]["shodan_internetdb"]["queried"] == 1
        assert result["provider_stats"]["shodan_internetdb"]["found"] == 1

    @patch("src.tools.threat_intel.enrich_single_ioc", side_effect=_mock_enrich)
    @patch("src.tools.threat_intel.get_investigation_client")
    def test_ioc_updated_with_enrichment(self, mock_get_client, mock_enrich, tools, client):
        mock_get_client.return_value = client
        _add_iocs(client, [_make_ioc("ip", "8.8.8.8", 4)])

        tools._enrich_iocs(None, None, 1, None, 20)

        ioc = client.active_investigation.iocs.iocs[0]
        assert ioc.is_malicious is True
        assert ioc.confidence == 0.75
        assert "shodan_internetdb" in ioc.context
        assert any(s.source_type == SourceType.THREAT_INTEL for s in ioc.sources)

    @patch("src.tools.threat_intel.enrich_single_ioc", side_effect=_mock_enrich)
    @patch("src.tools.threat_intel.get_investigation_client")
    def test_threat_intel_source_not_duplicated(self, mock_get_client, mock_enrich, tools, client):
        mock_get_client.return_value = client
        _add_iocs(client, [_make_ioc("ip", "8.8.8.8", 4)])

        tools._enrich_iocs(None, None, 1, None, 20)
        tools._enrich_iocs(None, None, 1, None, 20)

        ioc = client.active_investigation.iocs.iocs[0]
        ti_sources = [s for s in ioc.sources if s.source_type == SourceType.THREAT_INTEL]
        assert len(ti_sources) == 1


# ---------------------------------------------------------------------------
# Verdict classification thresholds
# ---------------------------------------------------------------------------


class TestVerdictClassification:
    @patch("src.tools.threat_intel.enrich_single_ioc")
    @patch("src.tools.threat_intel.aggregate_verdicts")
    @patch("src.tools.threat_intel.get_investigation_client")
    def test_high_confidence_malicious(self, mock_client, mock_agg, mock_enrich, tools, client):
        mock_client.return_value = client
        mock_enrich.return_value = []
        mock_agg.return_value = (True, 0.85)
        _add_iocs(client, [_make_ioc("ip", "1.1.1.1", 3)])

        result = tools._enrich_iocs(None, None, 1, None, 20)
        assert result["enriched_iocs"][0]["verdict"] == "malicious"
        assert result["verdicts"]["malicious"] == 1

    @patch("src.tools.threat_intel.enrich_single_ioc")
    @patch("src.tools.threat_intel.aggregate_verdicts")
    @patch("src.tools.threat_intel.get_investigation_client")
    def test_low_confidence_malicious_is_suspicious(self, mock_client, mock_agg, mock_enrich, tools, client):
        mock_client.return_value = client
        mock_enrich.return_value = []
        mock_agg.return_value = (True, 0.55)
        _add_iocs(client, [_make_ioc("ip", "1.1.1.1", 3)])

        result = tools._enrich_iocs(None, None, 1, None, 20)
        assert result["enriched_iocs"][0]["verdict"] == "suspicious"
        assert result["verdicts"]["suspicious"] == 1

    @patch("src.tools.threat_intel.enrich_single_ioc")
    @patch("src.tools.threat_intel.aggregate_verdicts")
    @patch("src.tools.threat_intel.get_investigation_client")
    def test_clean_verdict(self, mock_client, mock_agg, mock_enrich, tools, client):
        mock_client.return_value = client
        mock_enrich.return_value = []
        mock_agg.return_value = (False, 0.1)
        _add_iocs(client, [_make_ioc("ip", "1.1.1.1", 3)])

        result = tools._enrich_iocs(None, None, 1, None, 20)
        assert result["enriched_iocs"][0]["verdict"] == "clean"

    @patch("src.tools.threat_intel.enrich_single_ioc")
    @patch("src.tools.threat_intel.aggregate_verdicts")
    @patch("src.tools.threat_intel.get_investigation_client")
    def test_unknown_verdict(self, mock_client, mock_agg, mock_enrich, tools, client):
        mock_client.return_value = client
        mock_enrich.return_value = []
        mock_agg.return_value = (None, 0.5)
        _add_iocs(client, [_make_ioc("ip", "1.1.1.1", 3)])

        result = tools._enrich_iocs(None, None, 1, None, 20)
        assert result["enriched_iocs"][0]["verdict"] == "unknown"

    @patch("src.tools.threat_intel.enrich_single_ioc")
    @patch("src.tools.threat_intel.aggregate_verdicts")
    @patch("src.tools.threat_intel.get_investigation_client")
    def test_boundary_0_7_is_malicious(self, mock_client, mock_agg, mock_enrich, tools, client):
        mock_client.return_value = client
        mock_enrich.return_value = []
        mock_agg.return_value = (True, 0.7)
        _add_iocs(client, [_make_ioc("ip", "1.1.1.1", 3)])

        result = tools._enrich_iocs(None, None, 1, None, 20)
        assert result["enriched_iocs"][0]["verdict"] == "malicious"


# ---------------------------------------------------------------------------
# _lookup_ioc tests
# ---------------------------------------------------------------------------


class TestLookupIoc:
    @patch("src.tools.threat_intel.enrich_single_ioc", side_effect=_mock_enrich)
    def test_lookup_ip(self, mock_enrich, tools):
        result = tools._lookup_ioc("ip", "8.8.8.8", None)

        assert result["verdict"] == "malicious"
        assert result["confidence"] == 0.75
        assert "shodan_internetdb" in result["details"]

    @patch("src.tools.threat_intel.enrich_single_ioc", return_value=[])
    def test_lookup_unsupported_type_no_providers(self, mock_enrich, tools):
        result = tools._lookup_ioc("user", "admin", None)

        assert result["verdict"] == "unknown"
        assert "No providers support" in result["message"]

    def test_lookup_invalid_type(self, tools):
        result = tools._lookup_ioc("banana", "fruit", None)

        assert "error" in result
        assert "supported_types" in result

    @patch(
        "src.tools.threat_intel.enrich_single_ioc",
        return_value=[
            EnrichmentResult(
                provider="virustotal",
                ioc_type="hash",
                ioc_value="abc123",
                is_malicious=True,
                confidence=0.9,
                context={"detection_stats": {"malicious": 40}},
            )
        ],
    )
    def test_lookup_hash(self, mock_enrich, tools):
        result = tools._lookup_ioc("hash", "abc123", None)

        assert result["verdict"] == "malicious"
        assert result["ioc"]["type"] == "hash"
        assert "virustotal" in result["details"]

    @patch(
        "src.tools.threat_intel.enrich_single_ioc",
        return_value=[
            EnrichmentResult(
                provider="shodan_internetdb",
                ioc_type="ip",
                ioc_value="1.1.1.1",
                error="Connection error: timeout",
            )
        ],
    )
    def test_lookup_with_error(self, mock_enrich, tools):
        result = tools._lookup_ioc("ip", "1.1.1.1", None)

        assert result["verdict"] == "unknown"
        assert result["details"]["shodan_internetdb"]["error"] is not None


# ---------------------------------------------------------------------------
# _get_enrichment_status tests
# ---------------------------------------------------------------------------


class TestGetEnrichmentStatus:
    @patch.dict("os.environ", {}, clear=True)
    def test_no_keys_configured(self, tools):
        result = tools._get_enrichment_status()

        assert result["total_configured"] == 1  # Shodan always active
        assert result["providers"]["shodan_internetdb"]["configured"] is True
        assert result["providers"]["virustotal"]["configured"] is False
        assert len(result["recommendations"]) == 3  # VT, AbuseIPDB, ThreatFox

    @patch.dict(
        "os.environ",
        {
            "VIRUSTOTAL_API_KEY": "test-key",
            "ABUSEIPDB_API_KEY": "test-key",
            "THREATFOX_API_KEY": "test-key",
        },
    )
    def test_all_keys_configured(self, tools):
        result = tools._get_enrichment_status()

        assert result["total_configured"] == 4
        assert result["providers"]["virustotal"]["configured"] is True
        assert result["providers"]["abuseipdb"]["configured"] is True
        assert result["providers"]["threatfox"]["configured"] is True
        assert result["recommendations"] == ["All providers configured."]

    @patch.dict("os.environ", {"VIRUSTOTAL_API_KEY": "test-key"}, clear=True)
    def test_partial_keys(self, tools):
        result = tools._get_enrichment_status()

        assert result["total_configured"] == 2  # Shodan + VT
        assert len(result["recommendations"]) == 2  # AbuseIPDB + ThreatFox
