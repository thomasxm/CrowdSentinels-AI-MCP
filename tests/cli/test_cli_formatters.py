"""Tests for CLI output formatters — json, table, summary.

Covers all output shapes: health, hunt, analyse, rules, detect, pcap, beaconing.
"""

import json

from src.cli.main import _format_json, _format_summary, _format_table

# ---------------------------------------------------------------------------
# Sample data fixtures
# ---------------------------------------------------------------------------

HEALTH_DATA = {
    "cluster_name": "docker-cluster",
    "status": "yellow",
    "number_of_nodes": 1,
    "active_shards": 81,
    "unassigned_shards": 8,
}

HUNT_DATA = {
    "summary": {
        "total_hits": 120,
        "analyzed": 50,
        "severity": "high",
        "timeframe": "2017-06-09 to 2023-01-24",
    },
    "iocs": {
        "hostname": [
            {"value": "MSEDGEWIN10", "priority": 3},
            {"value": "LAPTOP-JU4M3I0E", "priority": 3},
        ]
    },
    "mitre_techniques": [
        {"technique_id": "T1110", "technique_name": "Brute Force", "tactic": "Credential Access", "count": 5}
    ],
    "insights": ["LATERAL SPREAD: Activity across 3 hosts"],
    "sample_events": [
        {"@timestamp": "2021-08-17T12:26:51Z", "code": "9", "name": "LAPTOP", "message": "RPC call failed"}
    ],
    "pagination": {"has_more": True, "guidance": "70 remaining"},
    "workflow_hint": {"next_step": "analyze_kill_chain_stage", "instruction": "Position in kill chain"},
}

ANALYSE_DATA = {
    "severity_assessment": "critical",
    "context": "PowerShell investigation",
    "summary": {"total_events": 4, "events_analyzed": 4},
    "mitre_attack_techniques": [
        {"technique_id": "T1059.001", "technique_name": "PowerShell ScriptBlock", "tactic": "Execution", "count": 4},
        {"technique_id": "T1003.001", "technique_name": "LSASS Memory Dump", "tactic": "Credential Access", "count": 2},
    ],
    "piped_iocs": {"hostname": [{"value": "MSEDGEWIN10", "priority": 3}]},
    "iocs_found": [{"type": "hostname", "value": "MSEDGEWIN10"}],
    "raw_insights": ["MITRE: 2 tactics detected"],
    "recommended_followup": [{"description": "Check lateral movement"}],
}

RULES_DATA = {
    "total_matching": 317,
    "showing": 3,
    "rules": [
        {
            "rule_id": "win_test_1",
            "name": "Test Rule 1",
            "platform": "windows",
            "log_source": "builtin",
            "type": "lucene",
            "mitre_tactics": ["credential_access"],
        },
        {
            "rule_id": "win_test_2",
            "name": "Test Rule 2",
            "platform": "windows",
            "log_source": "powershell",
            "type": "eql",
            "mitre_tactics": ["execution"],
        },
    ],
    "statistics": {"total_rules_loaded": 6061, "by_platform": {"windows": 4305}},
}

DETECT_DATA = {
    "response": {"lucene_query": "event.code:4625", "total_hits": 0, "events": []},
    "rule_info": {
        "rule_id": "win_alert_mimikatz",
        "name": "Win Alert Mimikatz Keywords",
        "type": "lucene",
        "mitre_tactics": ["credential_access"],
    },
    "field_substitutions": {"count": 1, "substitutions": {"event.code": "winlog.event_id"}},
}

PCAP_OVERVIEW_DATA = {
    "pcap_path": "/path/to/capture.pcap",
    "packet_count": 18523,
    "duration_seconds": 328490.0,
    "time_start": "1969-12-31 19:00:00",
    "time_end": "1970-01-04 14:14:50",
    "file_size_bytes": 3607077,
    "protocols": [
        {"protocol": "tcp", "packet_count": 5991, "byte_count": 1256280, "percentage": 6.9},
        {"protocol": "http", "packet_count": 941, "byte_count": 527476, "percentage": 1.1},
    ],
    "top_talkers": [
        {"ip": "10.0.2.16", "packet_count": 12589, "byte_count": 2560000, "is_internal": True},
        {"ip": "173.194.70.106", "packet_count": 3153, "byte_count": 583680, "is_internal": False},
    ],
}

BEACONING_DATA = {
    "pcap_path": "/path/to/capture.pcap",
    "beacons": [],
    "patterns": [
        {
            "src_ip": "10.0.2.16",
            "dst_ip": "173.194.70.106",
            "dst_port": 80,
            "interval_mean": 1047.5,
            "jitter_percent": 88.0,
            "occurrence_count": 313,
            "confidence": "MEDIUM",
        },
    ],
    "summary": {"total_patterns": 1, "high_confidence": 0, "medium_confidence": 1, "low_confidence": 0},
}


# ---------------------------------------------------------------------------
# JSON format tests
# ---------------------------------------------------------------------------


class TestFormatJson:
    def test_health_json(self):
        result = _format_json(HEALTH_DATA)
        parsed = json.loads(result)
        assert parsed["cluster_name"] == "docker-cluster"
        assert parsed["status"] == "yellow"

    def test_hunt_json(self):
        result = _format_json(HUNT_DATA)
        parsed = json.loads(result)
        assert parsed["summary"]["total_hits"] == 120

    def test_analyse_json(self):
        result = _format_json(ANALYSE_DATA)
        parsed = json.loads(result)
        assert parsed["severity_assessment"] == "critical"


# ---------------------------------------------------------------------------
# Table format tests
# ---------------------------------------------------------------------------


class TestFormatTable:
    def test_health_table(self):
        result = _format_table(HEALTH_DATA)
        assert "Cluster Health" in result
        assert "docker-cluster" in result
        assert "yellow" in result

    def test_hunt_table(self):
        result = _format_table(HUNT_DATA)
        assert "Summary" in result
        assert "total_hits: 120" in result
        assert "IoCs" in result
        assert "MSEDGEWIN10" in result
        assert "MITRE ATT&CK" in result
        assert "T1110" in result
        assert "Sample Events" in result
        assert "more results available" in result

    def test_analyse_table(self):
        result = _format_table(ANALYSE_DATA)
        assert "Analysis" in result
        assert "critical" in result
        assert "T1059.001" in result
        assert "T1003.001" in result
        assert "MSEDGEWIN10" in result
        assert "Recommended Follow-up" in result

    def test_rules_table(self):
        result = _format_table(RULES_DATA)
        assert "Rules (317)" in result
        assert "Test Rule 1" in result
        assert "credential_access" in result

    def test_detect_table(self):
        result = _format_table(DETECT_DATA)
        assert "Detection Rule" in result
        assert "Win Alert Mimikatz" in result
        assert "hits: 0" in result
        assert "No matching events found" in result

    def test_pcap_overview_table(self):
        result = _format_table(PCAP_OVERVIEW_DATA)
        assert "PCAP Overview" in result
        assert "packets: 18523" in result
        assert "Top Protocols" in result
        assert "tcp" in result
        assert "Top Talkers" in result
        assert "10.0.2.16" in result

    def test_beaconing_table(self):
        result = _format_table(BEACONING_DATA)
        assert "Beaconing Analysis" in result
        assert "total patterns: 1" in result
        assert "Detected Patterns" in result
        assert "173.194.70.106" in result
        assert "MEDIUM" in result

    def test_empty_dict_fallback(self):
        result = _format_table({"foo": "bar", "num": 42})
        assert "foo: bar" in result
        assert "num: 42" in result


# ---------------------------------------------------------------------------
# Summary format tests
# ---------------------------------------------------------------------------


class TestFormatSummary:
    def test_health_summary(self):
        result = _format_summary(HEALTH_DATA)
        assert "cluster=docker-cluster" in result
        assert "status=yellow" in result
        assert "nodes=1" in result

    def test_hunt_summary(self):
        result = _format_summary(HUNT_DATA)
        assert "hits=120" in result
        assert "severity=high" in result
        assert "iocs=2" in result
        assert "mitre=T1110" in result
        assert "has_more=true" in result

    def test_analyse_summary(self):
        result = _format_summary(ANALYSE_DATA)
        assert "severity=critical" in result
        assert "mitre=T1059.001,T1003.001" in result
        assert "iocs=" in result

    def test_rules_summary(self):
        result = _format_summary(RULES_DATA)
        assert "rules=317" in result

    def test_detect_summary(self):
        result = _format_summary(DETECT_DATA)
        assert "rule=Win Alert Mimikatz" in result
        assert "hits=0" in result
        assert "credential_access" in result

    def test_pcap_overview_summary(self):
        result = _format_summary(PCAP_OVERVIEW_DATA)
        assert "packets=18523" in result
        assert "protocols=2" in result

    def test_beaconing_summary(self):
        result = _format_summary(BEACONING_DATA)
        assert "patterns=1" in result
        assert "173.194.70.106" in result
        assert "MEDIUM" in result

    def test_empty_data(self):
        result = _format_summary({})
        assert result == ""  # No keys match any handler
