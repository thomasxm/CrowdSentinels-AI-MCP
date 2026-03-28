"""Tests for _populate_related_iocs functionality.

Covers:
- Same tool+query context links IoCs together
- Different tools/queries do NOT link
- Idempotency (re-running adds no duplicates)
- Three-way linking
- Single IoC stays unlinked
- Large set (20+) links correctly
- Integration with add_findings (related_iocs_linked in summary)
"""

import sys
from datetime import datetime
from pathlib import Path

import pytest

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


def _make_ioc(
    ioc_type: IoCType,
    value: str,
    tool: str = "manual",
    query_context: str | None = None,
    ioc_id: str | None = None,
) -> IoC:
    """Build an IoC with a specific source tool and query context."""
    kwargs: dict = {
        "type": ioc_type,
        "value": value,
        "sources": [
            IoCSource(
                tool=tool,
                source_type=SourceType.OTHER,
                query_context=query_context,
            ),
        ],
    }
    if ioc_id is not None:
        kwargs["id"] = ioc_id
    return IoC(**kwargs)


def _build_investigation(iocs: list[IoC]) -> Investigation:
    """Create an Investigation and populate its IoC collection directly."""
    inv = Investigation.create(name="related-test")
    for ioc in iocs:
        inv.iocs.add_ioc(ioc)
    return inv


# ---------------------------------------------------------------------------
# Core linking behaviour
# ---------------------------------------------------------------------------


class TestSameSourceLinking:
    """IoCs from the same tool+query_context should be linked."""

    def test_two_iocs_same_tool_query_linked(self) -> None:
        ioc_a = _make_ioc(IoCType.IP, "10.0.0.1", tool="es", query_context="q1", ioc_id="a1")
        ioc_b = _make_ioc(IoCType.DOMAIN, "evil.com", tool="es", query_context="q1", ioc_id="b1")
        inv = _build_investigation([ioc_a, ioc_b])

        links = InvestigationStateClient._populate_related_iocs(None, inv)

        assert links > 0
        iocs_map = {ioc.id: ioc for ioc in inv.iocs.iocs}
        assert "b1" in iocs_map["a1"].related_iocs
        assert "a1" in iocs_map["b1"].related_iocs

    def test_two_iocs_same_tool_default_query_linked(self) -> None:
        """When query_context is None, both fall into the default bucket."""
        ioc_a = _make_ioc(IoCType.IP, "10.0.0.2", tool="chainsaw", ioc_id="c1")
        ioc_b = _make_ioc(IoCType.HASH, "a" * 32, tool="chainsaw", ioc_id="c2")
        inv = _build_investigation([ioc_a, ioc_b])

        links = InvestigationStateClient._populate_related_iocs(None, inv)

        assert links > 0
        iocs_map = {ioc.id: ioc for ioc in inv.iocs.iocs}
        assert "c2" in iocs_map["c1"].related_iocs
        assert "c1" in iocs_map["c2"].related_iocs


class TestDifferentSourceNoLink:
    """IoCs from different tools or query contexts should NOT be linked."""

    def test_different_tools_not_linked(self) -> None:
        ioc_a = _make_ioc(IoCType.IP, "10.0.0.3", tool="es", query_context="q1", ioc_id="d1")
        ioc_b = _make_ioc(IoCType.DOMAIN, "other.com", tool="chainsaw", query_context="q1", ioc_id="d2")
        inv = _build_investigation([ioc_a, ioc_b])

        links = InvestigationStateClient._populate_related_iocs(None, inv)

        assert links == 0
        iocs_map = {ioc.id: ioc for ioc in inv.iocs.iocs}
        assert iocs_map["d1"].related_iocs == []
        assert iocs_map["d2"].related_iocs == []

    def test_same_tool_different_query_not_linked(self) -> None:
        ioc_a = _make_ioc(IoCType.IP, "10.0.0.4", tool="es", query_context="query-alpha", ioc_id="e1")
        ioc_b = _make_ioc(IoCType.DOMAIN, "other2.com", tool="es", query_context="query-beta", ioc_id="e2")
        inv = _build_investigation([ioc_a, ioc_b])

        links = InvestigationStateClient._populate_related_iocs(None, inv)

        assert links == 0
        iocs_map = {ioc.id: ioc for ioc in inv.iocs.iocs}
        assert iocs_map["e1"].related_iocs == []
        assert iocs_map["e2"].related_iocs == []


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------


class TestIdempotency:
    """Re-running _populate_related_iocs should not create duplicate entries."""

    def test_double_run_no_duplicates(self) -> None:
        ioc_a = _make_ioc(IoCType.IP, "10.1.1.1", tool="es", query_context="q1", ioc_id="f1")
        ioc_b = _make_ioc(IoCType.IP, "10.1.1.2", tool="es", query_context="q1", ioc_id="f2")
        inv = _build_investigation([ioc_a, ioc_b])

        first_links = InvestigationStateClient._populate_related_iocs(None, inv)
        second_links = InvestigationStateClient._populate_related_iocs(None, inv)

        assert first_links > 0
        assert second_links == 0  # No NEW links on second run

        iocs_map = {ioc.id: ioc for ioc in inv.iocs.iocs}
        # No duplicate IDs
        assert len(iocs_map["f1"].related_iocs) == len(set(iocs_map["f1"].related_iocs))
        assert len(iocs_map["f2"].related_iocs) == len(set(iocs_map["f2"].related_iocs))

    def test_triple_run_stable(self) -> None:
        iocs = [_make_ioc(IoCType.IP, f"10.2.2.{i}", tool="es", query_context="q1", ioc_id=f"g{i}") for i in range(5)]
        inv = _build_investigation(iocs)

        InvestigationStateClient._populate_related_iocs(None, inv)
        InvestigationStateClient._populate_related_iocs(None, inv)
        third_links = InvestigationStateClient._populate_related_iocs(None, inv)

        assert third_links == 0

        for ioc in inv.iocs.iocs:
            assert len(ioc.related_iocs) == len(set(ioc.related_iocs))


# ---------------------------------------------------------------------------
# Three-way linking
# ---------------------------------------------------------------------------


class TestThreeWayLinking:
    """Three IoCs from the same source should each reference the other two."""

    def test_three_iocs_fully_linked(self) -> None:
        ioc_a = _make_ioc(IoCType.IP, "10.3.3.1", tool="es", query_context="q1", ioc_id="h1")
        ioc_b = _make_ioc(IoCType.DOMAIN, "three.com", tool="es", query_context="q1", ioc_id="h2")
        ioc_c = _make_ioc(IoCType.URL, "https://three.com/c2", tool="es", query_context="q1", ioc_id="h3")
        inv = _build_investigation([ioc_a, ioc_b, ioc_c])

        InvestigationStateClient._populate_related_iocs(None, inv)

        iocs_map = {ioc.id: ioc for ioc in inv.iocs.iocs}
        assert set(iocs_map["h1"].related_iocs) == {"h2", "h3"}
        assert set(iocs_map["h2"].related_iocs) == {"h1", "h3"}
        assert set(iocs_map["h3"].related_iocs) == {"h1", "h2"}


# ---------------------------------------------------------------------------
# Single IoC
# ---------------------------------------------------------------------------


class TestSingleIoC:
    """A single IoC should remain unlinked."""

    def test_single_ioc_no_related(self) -> None:
        ioc_a = _make_ioc(IoCType.IP, "10.4.4.1", tool="es", query_context="q1", ioc_id="i1")
        inv = _build_investigation([ioc_a])

        links = InvestigationStateClient._populate_related_iocs(None, inv)

        assert links == 0
        assert inv.iocs.iocs[0].related_iocs == []


# ---------------------------------------------------------------------------
# Large set (20+ IoCs)
# ---------------------------------------------------------------------------


class TestLargeSet:
    """20+ IoCs from the same source should all be linked to each other."""

    def test_twenty_five_iocs_linked(self) -> None:
        count = 25
        iocs = [
            _make_ioc(
                IoCType.IP,
                f"10.5.5.{i}",
                tool="bulk-tool",
                query_context="bulk-query",
                ioc_id=f"j{i}",
            )
            for i in range(count)
        ]
        inv = _build_investigation(iocs)

        links = InvestigationStateClient._populate_related_iocs(None, inv)

        # Each IoC should link to (count - 1) others
        # Total new links = count * (count - 1) = 25 * 24 = 600
        assert links == count * (count - 1)

        for ioc in inv.iocs.iocs:
            assert len(ioc.related_iocs) == count - 1
            # Should not contain self
            assert ioc.id not in ioc.related_iocs

    def test_large_set_no_self_reference(self) -> None:
        count = 30
        iocs = [
            _make_ioc(
                IoCType.DOMAIN,
                f"host{i}.evil.com",
                tool="dns-tool",
                query_context="dns-scan",
                ioc_id=f"k{i}",
            )
            for i in range(count)
        ]
        inv = _build_investigation(iocs)

        InvestigationStateClient._populate_related_iocs(None, inv)

        for ioc in inv.iocs.iocs:
            assert ioc.id not in ioc.related_iocs


# ---------------------------------------------------------------------------
# Mixed sources
# ---------------------------------------------------------------------------


class TestMixedSources:
    """IoCs from multiple source groups should only link within their group."""

    def test_two_groups_independent(self) -> None:
        group_a = [
            _make_ioc(IoCType.IP, f"10.6.6.{i}", tool="es", query_context="alpha", ioc_id=f"la{i}") for i in range(3)
        ]
        group_b = [
            _make_ioc(IoCType.DOMAIN, f"host{i}.example.com", tool="chainsaw", query_context="beta", ioc_id=f"lb{i}")
            for i in range(3)
        ]
        inv = _build_investigation(group_a + group_b)

        InvestigationStateClient._populate_related_iocs(None, inv)

        a_ids = {ioc.id for ioc in group_a}
        b_ids = {f"lb{i}" for i in range(3)}

        iocs_map = {ioc.id: ioc for ioc in inv.iocs.iocs}

        # Group A IoCs only reference other group A IoCs
        for a_id in a_ids:
            assert set(iocs_map[a_id].related_iocs) == a_ids - {a_id}
            assert not set(iocs_map[a_id].related_iocs) & b_ids

        # Group B IoCs only reference other group B IoCs
        for b_id in b_ids:
            assert set(iocs_map[b_id].related_iocs) == b_ids - {b_id}
            assert not set(iocs_map[b_id].related_iocs) & a_ids


# ---------------------------------------------------------------------------
# Integration with add_findings
# ---------------------------------------------------------------------------


class TestAddFindingsIntegration:
    """Verify add_findings returns related_iocs_linked in its summary."""

    def test_add_findings_summary_contains_related_iocs_linked(self, client: InvestigationStateClient) -> None:
        inv = client.create_investigation("findings-integration")

        # Provide minimal ES-style results that the extractor can parse
        results = {
            "hits": {
                "total": {"value": 2, "relation": "eq"},
                "hits": [
                    {
                        "_source": {
                            "source": {"ip": "10.7.7.1"},
                            "destination": {"ip": "10.7.7.2"},
                            "event": {"action": "connection_attempted"},
                            "@timestamp": datetime.utcnow().isoformat(),
                        }
                    },
                    {
                        "_source": {
                            "source": {"ip": "10.7.7.3"},
                            "user": {"name": "admin"},
                            "event": {"action": "logon"},
                            "@timestamp": datetime.utcnow().isoformat(),
                        }
                    },
                ],
            }
        }

        summary = client.add_findings(
            source_type=SourceType.ELASTICSEARCH,
            source_tool="es-hunt",
            results=results,
            query_description="test query",
        )

        assert "related_iocs_linked" in summary
        # The value is an integer (could be 0 if no IoCs extracted, but key must exist)
        assert isinstance(summary["related_iocs_linked"], int)

    def test_add_findings_related_count_positive_when_iocs_share_source(self, client: InvestigationStateClient) -> None:
        """Pre-seed IoCs with same tool+query, then call add_findings to trigger linking."""
        inv = client.create_investigation("pre-seed")

        # Manually add IoCs that share a source
        ioc_a = _make_ioc(IoCType.IP, "10.8.8.1", tool="es-hunt", query_context="default")
        ioc_b = _make_ioc(IoCType.IP, "10.8.8.2", tool="es-hunt", query_context="default")
        client.add_iocs([ioc_a, ioc_b])

        # Now call add_findings which triggers _populate_related_iocs internally
        results = {
            "hits": {
                "total": {"value": 0, "relation": "eq"},
                "hits": [],
            }
        }
        summary = client.add_findings(
            source_type=SourceType.ELASTICSEARCH,
            source_tool="es-hunt",
            results=results,
        )

        assert "related_iocs_linked" in summary
        assert summary["related_iocs_linked"] >= 2
