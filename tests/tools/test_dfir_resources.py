"""Tests for DFIRResources MCP resources."""

from unittest.mock import MagicMock

from src.storage.models import IoCType, SourceType
from src.storage.smart_extractor import MITRE_EVENT_MAPPING
from src.tools.dfir_resources import (
    CROSS_CORRELATION_PLAYBOOKS,
    DATA_SOURCES,
    DFIRResources,
    _build_ioc_reference,
    _build_ioc_reference_data,
)


class TestDFIRResourcesRegistration:
    """Test that all resources register correctly."""

    def test_registers_all_resources(self):
        """All 4 expected resources should be registered."""
        resources = DFIRResources()
        mcp = MagicMock()

        registered_uris = []

        def mock_resource(uri):
            def decorator(func):
                registered_uris.append(uri)
                return func
            return decorator

        mcp.resource = mock_resource
        # Also mock mcp.tool since register_tools might register both
        mcp.tool = lambda: lambda f: f

        resources.register_tools(mcp)

        expected = [
            "crowdsentinel://data-sources",
            "crowdsentinel://ioc-reference",
            "crowdsentinel://ioc-reference/data",
            "crowdsentinel://cross-correlation-playbooks",
        ]
        for uri in expected:
            assert uri in registered_uris, f"Missing resource: {uri}"


class TestDataSourcesResource:
    """Test the data-sources resource content."""

    def test_mentions_all_source_types(self):
        """Resource should reference all configured data sources."""
        for source in ["Elasticsearch", "Chainsaw", "Wireshark", "Velociraptor", "Threat Intel"]:
            assert source in DATA_SOURCES, f"Missing data source: {source}"

    def test_includes_decision_matrix(self):
        """Resource should include the investigation decision matrix."""
        assert "Investigation Decision Matrix" in DATA_SOURCES

    def test_mentions_key_tools(self):
        """Resource should reference important tools."""
        for tool in ["threat_hunt_search", "velociraptor_pslist", "detect_beaconing", "hunt_with_sigma_rules"]:
            assert tool in DATA_SOURCES, f"Missing tool reference: {tool}"

    def test_mentions_prerequisites(self):
        """Resource should describe prerequisites for each source."""
        assert "ELASTICSEARCH_HOSTS" in DATA_SOURCES
        assert "VELOCIRAPTOR_API_CONFIG" in DATA_SOURCES
        assert "tshark" in DATA_SOURCES


class TestIoCReferenceResource:
    """Test the ioc-reference resource content."""

    def test_contains_all_ioc_types(self):
        """Markdown should mention all IoC types."""
        md = _build_ioc_reference()
        for ioc_type in IoCType:
            assert ioc_type.value in md, f"Missing IoC type: {ioc_type.value}"

    def test_contains_all_priority_levels(self):
        """Markdown should show all Pyramid of Pain levels."""
        md = _build_ioc_reference()
        for level in ["Trivial", "Easy", "Simple", "Annoying", "Challenging", "Tough"]:
            assert level in md, f"Missing priority level: {level}"

    def test_contains_mitre_table(self):
        """Markdown should include MITRE ATT&CK event ID table."""
        md = _build_ioc_reference()
        assert "MITRE ATT&CK Event ID Quick Reference" in md
        for event_id in MITRE_EVENT_MAPPING:
            assert str(event_id) in md, f"Missing event ID: {event_id}"

    def test_priority_ordering(self):
        """Higher priorities should appear before lower ones."""
        md = _build_ioc_reference()
        pos_6 = md.index("Priority 6")
        pos_1 = md.index("Priority 1")
        assert pos_6 < pos_1, "Priority 6 (TTPs) should appear before Priority 1 (Trivial)"


class TestIoCReferenceDataResource:
    """Test the machine-readable ioc-reference/data resource."""

    def test_structure(self):
        """Data should have expected top-level keys."""
        data = _build_ioc_reference_data()
        assert "pyramid_of_pain" in data
        assert "mitre_event_mapping" in data
        assert "ioc_types" in data
        assert "source_types" in data

    def test_pyramid_contains_all_ioc_types(self):
        """Pyramid should have an entry for every IoCType."""
        data = _build_ioc_reference_data()
        for ioc_type in IoCType:
            assert ioc_type.value in data["pyramid_of_pain"], f"Missing: {ioc_type.value}"

    def test_pyramid_entry_structure(self):
        """Each pyramid entry should have priority and level."""
        data = _build_ioc_reference_data()
        for ioc_type, entry in data["pyramid_of_pain"].items():
            assert "priority" in entry, f"Missing priority for {ioc_type}"
            assert "level" in entry, f"Missing level for {ioc_type}"
            assert isinstance(entry["priority"], int)
            assert 1 <= entry["priority"] <= 6

    def test_mitre_mapping_matches_source(self):
        """MITRE data should match the source MITRE_EVENT_MAPPING."""
        data = _build_ioc_reference_data()
        assert len(data["mitre_event_mapping"]) == len(MITRE_EVENT_MAPPING)
        for event_id in MITRE_EVENT_MAPPING:
            assert event_id in data["mitre_event_mapping"]

    def test_ioc_types_list(self):
        """ioc_types should list all IoCType values."""
        data = _build_ioc_reference_data()
        assert set(data["ioc_types"]) == {t.value for t in IoCType}

    def test_source_types_list(self):
        """source_types should list all SourceType values."""
        data = _build_ioc_reference_data()
        assert set(data["source_types"]) == {s.value for s in SourceType}


class TestCrossCorrelationPlaybooksResource:
    """Test the cross-correlation playbooks content."""

    def test_contains_all_playbooks(self):
        """Should contain all 5 named playbooks."""
        for playbook in [
            "Suspicious Process",
            "Brute Force",
            "Lateral Movement",
            "Persistence Discovery",
            "Data Exfiltration",
        ]:
            assert playbook in CROSS_CORRELATION_PLAYBOOKS, f"Missing playbook: {playbook}"

    def test_contains_kill_chain_mapping(self):
        """Should include kill chain to data source mapping."""
        assert "Kill Chain" in CROSS_CORRELATION_PLAYBOOKS
        assert "Reconnaissance" in CROSS_CORRELATION_PLAYBOOKS
        assert "Actions on Objectives" in CROSS_CORRELATION_PLAYBOOKS

    def test_contains_mitre_tactic_mapping(self):
        """Should include MITRE tactic to tool mapping."""
        assert "MITRE Tactic" in CROSS_CORRELATION_PLAYBOOKS
        assert "Credential Access" in CROSS_CORRELATION_PLAYBOOKS

    def test_references_velociraptor_tools(self):
        """Playbooks should reference Velociraptor tools for endpoint validation."""
        for tool in ["velociraptor_pslist", "velociraptor_prefetch", "velociraptor_services"]:
            assert tool in CROSS_CORRELATION_PLAYBOOKS, f"Missing tool: {tool}"

    def test_references_siem_tools(self):
        """Playbooks should reference SIEM tools."""
        for tool in ["threat_hunt_search", "hunt_for_ioc", "hunt_by_timeframe"]:
            assert tool in CROSS_CORRELATION_PLAYBOOKS, f"Missing tool: {tool}"

    def test_references_cross_correlation_tools(self):
        """Playbooks should reference the cross-correlation tools."""
        assert "correlate_siem_with_endpoint" in CROSS_CORRELATION_PLAYBOOKS
        assert "build_unified_timeline" in CROSS_CORRELATION_PLAYBOOKS
