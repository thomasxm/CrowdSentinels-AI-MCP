"""Tests for MISP client — offline event creation and export."""

import json
from unittest.mock import MagicMock, patch

from src.clients.common.misp_client import (
    HASH_LENGTH_TO_TYPE,
    IOC_TYPE_TO_CATEGORY,
    IOC_TYPE_TO_MISP,
    build_misp_event,
    push_to_misp,
    search_misp_iocs,
)
from src.storage.models import IoC, IoCType


def _make_ioc(ioc_type: str, value: str, priority: int = 3, **kwargs) -> IoC:
    return IoC(type=IoCType(ioc_type), value=value, pyramid_priority=priority, **kwargs)


# ---------------------------------------------------------------------------
# build_misp_event
# ---------------------------------------------------------------------------


class TestBuildMispEvent:
    def test_basic_event_structure(self):
        iocs = [_make_ioc("ip", "1.2.3.4", 4)]
        result = build_misp_event("Test", "INV-001", iocs)

        assert "Event" in result or "info" in result
        # MISPEvent.to_dict() returns the event dict directly
        info = result.get("info", "")
        assert "CrowdSentinel" in info
        assert "INV-001" in info

    def test_ip_maps_to_ip_dst(self):
        iocs = [_make_ioc("ip", "10.0.0.1", 4)]
        result = build_misp_event("Test", "INV-001", iocs)

        attrs = result.get("Attribute", [])
        assert len(attrs) >= 1
        assert attrs[0]["type"] == "ip-dst"
        assert attrs[0]["value"] == "10.0.0.1"

    def test_domain_maps_correctly(self):
        iocs = [_make_ioc("domain", "evil.com", 3)]
        result = build_misp_event("Test", "INV-001", iocs)

        attrs = result.get("Attribute", [])
        assert any(a["type"] == "domain" and a["value"] == "evil.com" for a in attrs)

    def test_hash_md5(self):
        iocs = [_make_ioc("hash", "d" * 32, 5)]
        result = build_misp_event("Test", "INV-001", iocs)

        attrs = result.get("Attribute", [])
        assert any(a["type"] == "md5" for a in attrs)

    def test_hash_sha1(self):
        iocs = [_make_ioc("hash", "a" * 40, 5)]
        result = build_misp_event("Test", "INV-001", iocs)

        attrs = result.get("Attribute", [])
        assert any(a["type"] == "sha1" for a in attrs)

    def test_hash_sha256(self):
        iocs = [_make_ioc("hash", "b" * 64, 5)]
        result = build_misp_event("Test", "INV-001", iocs)

        attrs = result.get("Attribute", [])
        assert any(a["type"] == "sha256" for a in attrs)

    def test_url_maps_correctly(self):
        iocs = [_make_ioc("url", "http://evil.com/payload", 4)]
        result = build_misp_event("Test", "INV-001", iocs)

        attrs = result.get("Attribute", [])
        assert any(a["type"] == "url" for a in attrs)

    def test_email_maps_to_email_src(self):
        iocs = [_make_ioc("email", "bad@evil.com", 3)]
        result = build_misp_event("Test", "INV-001", iocs)

        attrs = result.get("Attribute", [])
        assert any(a["type"] == "email-src" for a in attrs)

    def test_registry_key_maps_to_regkey(self):
        iocs = [_make_ioc("registry_key", r"HKLM\Software\Evil", 5)]
        result = build_misp_event("Test", "INV-001", iocs)

        attrs = result.get("Attribute", [])
        assert any(a["type"] == "regkey" for a in attrs)

    def test_multiple_iocs(self):
        iocs = [
            _make_ioc("ip", "1.2.3.4", 4),
            _make_ioc("domain", "evil.com", 3),
            _make_ioc("hash", "a" * 64, 5),
        ]
        result = build_misp_event("Test", "INV-001", iocs)

        attrs = result.get("Attribute", [])
        assert len(attrs) == 3

    def test_empty_iocs(self):
        result = build_misp_event("Test", "INV-001", [])

        attrs = result.get("Attribute", [])
        assert len(attrs) == 0

    def test_threat_level_mapping(self):
        iocs = [_make_ioc("ip", "1.2.3.4")]
        result = build_misp_event("Test", "INV-001", iocs, severity="critical")
        assert result.get("threat_level_id") == "1"

        result = build_misp_event("Test", "INV-001", iocs, severity="low")
        assert result.get("threat_level_id") == "3"

    def test_tags_added(self):
        iocs = [_make_ioc("ip", "1.2.3.4")]
        result = build_misp_event("Test", "INV-001", iocs, tags=["tlp:amber"])

        tags = result.get("Tag", [])
        tag_names = [t.get("name", "") for t in tags]
        assert "tlp:amber" in tag_names
        assert "crowdsentinel:auto-export" in tag_names

    def test_to_ids_high_priority(self):
        iocs = [_make_ioc("ip", "1.2.3.4", 5, is_malicious=True)]
        result = build_misp_event("Test", "INV-001", iocs)

        attrs = result.get("Attribute", [])
        assert attrs[0]["to_ids"] is True

    def test_to_ids_false_for_clean(self):
        iocs = [_make_ioc("ip", "8.8.8.8", 3, is_malicious=False)]
        result = build_misp_event("Test", "INV-001", iocs)

        attrs = result.get("Attribute", [])
        assert attrs[0]["to_ids"] is False

    def test_comment_includes_verdict(self):
        iocs = [_make_ioc("ip", "1.2.3.4", 4, is_malicious=True)]
        result = build_misp_event("Test", "INV-001", iocs)

        attrs = result.get("Attribute", [])
        assert "malicious" in attrs[0].get("comment", "")

    def test_roundtrip_json(self):
        iocs = [_make_ioc("ip", "1.2.3.4", 4)]
        result = build_misp_event("Test", "INV-001", iocs)

        # Should be serialisable
        json_str = json.dumps(result, default=str)
        parsed = json.loads(json_str)
        assert parsed.get("info") is not None


# ---------------------------------------------------------------------------
# push_to_misp
# ---------------------------------------------------------------------------


class TestPushToMisp:
    @patch.dict("os.environ", {}, clear=True)
    def test_no_config_returns_not_pushed(self):
        result = push_to_misp({"info": "test"})
        assert result["pushed"] is False
        assert "not configured" in result["reason"]

    @patch.dict("os.environ", {"MISP_URL": "https://misp.test", "MISP_API_KEY": "testkey"})
    @patch("pymisp.PyMISP")
    def test_successful_push(self, mock_pymisp_cls):
        mock_misp = MagicMock()
        mock_result = MagicMock()
        mock_result.id = 42
        mock_result.uuid = "test-uuid-1234"
        mock_misp.add_event.return_value = mock_result
        mock_pymisp_cls.return_value = mock_misp

        result = push_to_misp({"info": "test"})
        assert result["pushed"] is True
        assert result["event_id"] == 42

    @patch.dict("os.environ", {"MISP_URL": "https://misp.test", "MISP_API_KEY": "testkey"})
    @patch("pymisp.PyMISP")
    def test_push_connection_error(self, mock_pymisp_cls):
        mock_pymisp_cls.side_effect = ConnectionError("refused")

        result = push_to_misp({"info": "test"})
        assert result["pushed"] is False
        assert "refused" in result["reason"]


# ---------------------------------------------------------------------------
# search_misp_iocs
# ---------------------------------------------------------------------------


class TestSearchMispIocs:
    @patch.dict("os.environ", {}, clear=True)
    def test_no_config_returns_empty(self):
        result = search_misp_iocs("1.2.3.4")
        assert result == []

    @patch.dict("os.environ", {"MISP_URL": "https://misp.test", "MISP_API_KEY": "testkey"})
    @patch("pymisp.PyMISP")
    def test_search_returns_matches(self, mock_pymisp_cls):
        mock_attr = MagicMock()
        mock_attr.type = "ip-dst"
        mock_attr.value = "1.2.3.4"
        mock_attr.event_id = 10
        mock_attr.category = "Network activity"
        mock_attr.to_ids = True
        mock_attr.comment = "C2 IP"
        mock_attr.Tag = []

        mock_misp = MagicMock()
        mock_misp.search.return_value = [mock_attr]
        mock_pymisp_cls.return_value = mock_misp

        result = search_misp_iocs("1.2.3.4", "ip")
        assert len(result) == 1
        assert result[0]["value"] == "1.2.3.4"
        assert result[0]["event_id"] == 10

    @patch.dict("os.environ", {"MISP_URL": "https://misp.test", "MISP_API_KEY": "testkey"})
    @patch("pymisp.PyMISP")
    def test_search_connection_error_returns_empty(self, mock_pymisp_cls):
        mock_pymisp_cls.side_effect = ConnectionError("timeout")

        result = search_misp_iocs("1.2.3.4")
        assert result == []


# ---------------------------------------------------------------------------
# Mapping completeness
# ---------------------------------------------------------------------------


class TestMappings:
    def test_all_ioc_types_have_misp_mapping(self):
        for ioc_type in IoCType:
            assert ioc_type.value in IOC_TYPE_TO_MISP or ioc_type.value == "hash"

    def test_all_ioc_types_have_category(self):
        for ioc_type in IoCType:
            assert ioc_type.value in IOC_TYPE_TO_CATEGORY or ioc_type.value == "hash"

    def test_hash_lengths_cover_common_algorithms(self):
        assert 32 in HASH_LENGTH_TO_TYPE  # MD5
        assert 40 in HASH_LENGTH_TO_TYPE  # SHA-1
        assert 64 in HASH_LENGTH_TO_TYPE  # SHA-256
