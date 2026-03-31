"""MCP Resources exposing structured DFIR knowledge to connected AI agents.

Provides investigation reference data — data source capabilities, IoC priority
(Pyramid of Pain), MITRE mappings, and cross-correlation playbooks — so agents
can make informed decisions without this knowledge being buried in code.
"""

from fastmcp import FastMCP

from src.storage.models import IoCType, SourceType
from src.storage.smart_extractor import MITRE_EVENT_MAPPING, PYRAMID_PRIORITY

# ---------------------------------------------------------------------------
# Pyramid of Pain level names
# ---------------------------------------------------------------------------
_PYRAMID_LEVELS = {
    1: "Trivial",
    2: "Easy",
    3: "Simple",
    4: "Annoying",
    5: "Challenging",
    6: "Tough (TTPs)",
}

# ---------------------------------------------------------------------------
# Data Sources reference
# ---------------------------------------------------------------------------
DATA_SOURCES = """
# CrowdSentinel Data Sources

## Elasticsearch / OpenSearch (SIEM)
- **What**: Centralized log aggregation — Windows Security, Sysmon, network, application logs
- **IoC extraction**: IP, domain, user, hostname, process, command line, file hash, file path, registry key
- **When to use**: Starting point for all investigations. Broad visibility across all endpoints.
- **Key tools**: `threat_hunt_search`, `smart_search`, `eql_search`, `esql_query`, `hunt_by_timeframe`, `hunt_for_ioc`
- **Prerequisites**: `ELASTICSEARCH_HOSTS` + `ELASTICSEARCH_API_KEY` or `ELASTICSEARCH_USERNAME`/`PASSWORD`

## Chainsaw (Offline EVTX)
- **What**: Sigma-based detection on raw Windows Event Log (.evtx) files
- **IoC extraction**: Process, command line, file hash (from detection rules)
- **When to use**: Offline forensics, dead-box analysis, when SIEM data is unavailable or incomplete
- **Key tools**: `hunt_with_sigma_rules`, `chainsaw_search`
- **Prerequisites**: Chainsaw binary installed (`crowdsentinel setup`), EVTX files accessible

## Wireshark (Network PCAP)
- **What**: Deep packet inspection of network captures via tshark
- **IoC extraction**: IP (src/dst), domain (DNS), URL
- **When to use**: Network-layer investigation — C2 beaconing, data exfiltration, DNS tunneling, lateral movement
- **Key tools**: `pcap_overview`, `detect_beaconing`, `detect_lateral_movement`, `hunt_iocs_in_pcap`
- **Prerequisites**: `tshark` installed, PCAP files accessible

## Velociraptor (Live Endpoint Forensics)
- **What**: Live forensic artifact collection from endpoints via gRPC
- **IoC extraction**: Process, command line, file path, IP, hash, user, hostname, service, URL, registry key
- **When to use**: Validating SIEM findings on live endpoints, evidence of execution, persistence hunting
- **Key tools**: `velociraptor_pslist`, `velociraptor_netstat`, `velociraptor_prefetch`, `velociraptor_amcache`, `velociraptor_services`, `velociraptor_scheduled_tasks`, `velociraptor_ntfs_mft`
- **Prerequisites**: `VELOCIRAPTOR_API_CONFIG` env var pointing to `api_client.yaml`
- **Note**: Only available when Velociraptor is configured

## Threat Intelligence (External Enrichment)
- **What**: External IoC enrichment via VirusTotal, AbuseIPDB, Shodan, MISP
- **IoC enrichment**: Reputation scores, threat context, known malware families
- **When to use**: After extracting IoCs, to determine if they match known threats
- **Key tools**: `enrich_iocs`, `lookup_ioc`, `export_to_misp`
- **Prerequisites**: API keys for desired providers (`VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, etc.)

---

## Investigation Decision Matrix

| Scenario | Start With | Then | Then |
|----------|-----------|------|------|
| Alert triage | Elasticsearch (SIEM) | Velociraptor (validate) | Threat Intel (context) |
| Lateral movement | Elasticsearch (4624 Type 3/10) | Velociraptor (Prefetch/Amcache) | Wireshark (SMB flows) |
| Malware analysis | Chainsaw (Sigma detection) | Velociraptor (execution evidence) | Threat Intel (hash lookup) |
| Data exfiltration | Wireshark (large transfers) | Elasticsearch (user activity) | Velociraptor (staging tools) |
| Persistence hunt | Velociraptor (services/tasks) | Elasticsearch (deployment timeline) | Threat Intel (hash/URL) |
| Offline forensics | Chainsaw (EVTX files) | Wireshark (PCAPs) | Threat Intel (extracted IoCs) |
"""

# ---------------------------------------------------------------------------
# IoC Reference (Pyramid of Pain)
# ---------------------------------------------------------------------------


def _build_ioc_reference() -> str:
    """Build the IoC reference markdown from model data."""
    lines = [
        "# IoC Reference — Pyramid of Pain",
        "",
        "IoCs ranked by how difficult they are for an attacker to change.",
        "**Focus hunting effort on higher priorities** — they cause the most pain.",
        "",
    ]

    # Group IoC types by priority level (descending)
    by_priority: dict[int, list[str]] = {}
    for ioc_type, priority in PYRAMID_PRIORITY.items():
        by_priority.setdefault(priority, []).append(ioc_type.value)

    descriptions = {
        IoCType.COMMANDLINE: "Encoded PowerShell, certutil downloads, LSASS access patterns. Forces adversary to redesign attack methodology.",
        IoCType.PROCESS: "mimikatz.exe, psexec.exe, cobalt strike beacons. Forces adversary to retool entirely.",
        IoCType.USER: "Compromised accounts, service accounts used for lateral movement.",
        IoCType.HOSTNAME: "Affected systems — track scope of compromise.",
        IoCType.FILE_PATH: "Malware staging directories, persistence locations (C:\\ProgramData, AppData\\Roaming).",
        IoCType.REGISTRY_KEY: "Run keys, service registrations, scheduled task entries.",
        IoCType.SERVICE: "Malicious services installed for persistence.",
        IoCType.SCHEDULED_TASK: "Scheduled tasks created for persistence or recurring execution.",
        IoCType.DOMAIN: "C2 domains, phishing infrastructure. Takes effort to register new ones.",
        IoCType.URL: "Payload download URLs, C2 callback paths.",
        IoCType.EMAIL: "Phishing sender addresses, exfiltration targets.",
        IoCType.IP: "C2 server IPs, scanning sources. Easily rotated by adversary.",
        IoCType.HASH: "File hashes (MD5/SHA1/SHA256). Trivially changed by recompiling.",
        IoCType.OTHER: "Uncategorized indicators.",
    }

    for priority in sorted(by_priority.keys(), reverse=True):
        level = _PYRAMID_LEVELS.get(priority, "Unknown")
        ioc_names = by_priority[priority]
        lines.append(f"## Priority {priority} — {level}")
        lines.append("")
        for name in ioc_names:
            ioc_type = IoCType(name)
            desc = descriptions.get(ioc_type, "")
            lines.append(f"### {name}")
            if desc:
                lines.append(f"- {desc}")
            lines.append("")

    # MITRE Event ID table
    lines.append("## MITRE ATT&CK Event ID Quick Reference")
    lines.append("")
    lines.append("| Event ID | Technique | Tactic | Description |")
    lines.append("|----------|-----------|--------|-------------|")
    for event_id, mapping in sorted(MITRE_EVENT_MAPPING.items(), key=lambda x: str(x[0])):
        lines.append(f"| {event_id} | {mapping['technique']} | {mapping['tactic']} | {mapping['name']} |")
    lines.append("")

    return "\n".join(lines)


def _build_ioc_reference_data() -> dict:
    """Build machine-readable IoC reference data."""
    pyramid = {}
    for ioc_type, priority in PYRAMID_PRIORITY.items():
        pyramid[ioc_type.value] = {
            "priority": priority,
            "level": _PYRAMID_LEVELS.get(priority, "Unknown"),
        }

    return {
        "pyramid_of_pain": pyramid,
        "mitre_event_mapping": {
            eid: dict(mapping) for eid, mapping in MITRE_EVENT_MAPPING.items()
        },
        "ioc_types": [t.value for t in IoCType],
        "source_types": [s.value for s in SourceType],
    }


# ---------------------------------------------------------------------------
# Cross-Correlation Playbooks
# ---------------------------------------------------------------------------
CROSS_CORRELATION_PLAYBOOKS = """
# Cross-Correlation Investigation Playbooks

Step-by-step workflows that pivot between data sources for complete investigations.

---

## Playbook 1: Suspicious Process — SIEM to Endpoint

**Trigger**: Suspicious process name or encoded command line detected in SIEM
**Kill Chain**: Exploitation -> Installation

1. `threat_hunt_search` — search for the process name across all hosts
2. `analyze_search_results` — extract IoCs, map MITRE ATT&CK techniques
3. `velociraptor_client_info` — resolve affected hostname to client_id
4. `velociraptor_pslist` — check if process is still running on endpoint
5. `velociraptor_prefetch` — confirm execution history (run count, timestamps)
6. `velociraptor_amcache` — get SHA1 hash and publisher of the binary
7. `hunt_for_ioc` with SHA1 hash — find same binary across other hosts (lateral movement)
8. `velociraptor_shimcache` — timeline of first appearance on this host

---

## Playbook 2: Brute Force — Detection to Containment

**Trigger**: Multiple failed logons (Event 4625) exceeding threshold
**Kill Chain**: Delivery -> Exploitation

1. `hunt_by_timeframe` with `attack_types=["brute_force"]` — gather failed logon events
2. `analyze_search_results` — identify target accounts and source IPs
3. `hunt_for_ioc(ioc_type="ip")` — find other activity from attacker IPs
4. Search for Event 4624 (successful logon) after failures — was account compromised?
5. If compromised: `velociraptor_pslist` on target host — what's running under that account?
6. `velociraptor_scheduled_tasks` + `velociraptor_services` — check for persistence

---

## Playbook 3: Lateral Movement — Multi-Host Correlation

**Trigger**: Event 4624 LogonType 3 (Network) or 10 (Remote Interactive) from unexpected source
**Kill Chain**: Actions on Objectives

1. `threat_hunt_search` for lateral_movement patterns
2. Identify source and target hosts from authentication events
3. `velociraptor_prefetch` on target — what executed immediately after logon?
4. `velociraptor_netstat` on source — active connections to other hosts?
5. `endpoint_to_siem_pivot(artifact_type="prefetch")` — find same tools on other hosts
6. `build_unified_timeline` — establish attack chronology across all sources

---

## Playbook 4: Persistence Discovery — Endpoint-First

**Trigger**: Suspicious service, scheduled task, or registry modification alert
**Kill Chain**: Installation

1. `velociraptor_services` — list all services, check for unsigned/suspicious DLLs
2. `velociraptor_scheduled_tasks` — check for encoded or obfuscated commands
3. Extract file hashes and paths as IoCs
4. `hunt_for_ioc` with hashes/paths across SIEM — when were these deployed? From where?
5. `analyze_kill_chain_stage` — confirm Installation stage
6. Hunt adjacent stage (C2): `hunt_by_kill_chain_stage("command_and_control")`

---

## Playbook 5: Data Exfiltration — Network + SIEM + Endpoint

**Trigger**: Large outbound transfers, archive tool usage, or DNS anomalies
**Kill Chain**: Actions on Objectives

1. `detect_beaconing` (Wireshark) or SIEM search for large outbound transfers
2. Identify destination IPs and domains
3. `threat_hunt_search` for those IPs/domains across all SIEM indices
4. `velociraptor_recentdocs` — what files were accessed on the endpoint?
5. `velociraptor_evidence_of_download` — were staging/archival tools downloaded?
6. `pcap_dns_analysis` — check for DNS tunneling
7. `correlate_siem_with_endpoint` — comprehensive cross-source validation

---

## Kill Chain -> Data Source Mapping

| Kill Chain Stage | Primary Sources | Secondary Sources | Key Event Codes |
|-----------------|-----------------|-------------------|-----------------|
| Reconnaissance | Firewall, IDS, DNS logs | Wireshark | — |
| Weaponization | Threat Intel, Sandbox | — | — |
| Delivery | Email gateway, Proxy logs | Elasticsearch | — |
| Exploitation | Sysmon (1), Security (4688) | Velociraptor | 4688, 4624 |
| Installation | Sysmon (1,11,13), Security | Velociraptor | 4697, 4698, 7045 |
| Command & Control | Firewall, Proxy, DNS | Wireshark | — |
| Actions on Objectives | Security logs, DLP | Velociraptor, Wireshark | 4624, 4648, 5140 |

## MITRE Tactic -> Best Starting Tool

| MITRE Tactic | Kill Chain Stage | Best Starting Tool |
|---|---|---|
| Reconnaissance | Reconnaissance | `threat_hunt_search` (firewall/DNS logs) |
| Initial Access | Delivery | `threat_hunt_search` (email/proxy logs) |
| Execution | Exploitation | `hunt_by_timeframe(["suspicious_process"])` |
| Persistence | Installation | `velociraptor_services` + `velociraptor_scheduled_tasks` |
| Privilege Escalation | Exploitation | `hunt_by_timeframe(["privilege_escalation"])` |
| Defense Evasion | Exploitation | `hunt_by_timeframe(["suspicious_process"])` |
| Credential Access | Actions | `hunt_by_timeframe(["credential_access"])` |
| Discovery | Actions | `velociraptor_pslist` (recon tools running) |
| Lateral Movement | Actions | `hunt_by_timeframe(["lateral_movement"])` |
| Collection | Actions | `velociraptor_recentdocs` + `velociraptor_shellbags` |
| Command and Control | C2 | `detect_beaconing` (Wireshark) or DNS analysis |
| Exfiltration | Actions | Wireshark + SIEM large-transfer hunt |
| Impact | Actions | `threat_hunt_search` (ransomware indicators) |
"""


# ---------------------------------------------------------------------------
# Registration class
# ---------------------------------------------------------------------------
class DFIRResources:
    """MCP resources exposing structured DFIR knowledge."""

    def register_tools(self, mcp: FastMCP):
        """Register DFIR knowledge resources with MCP."""

        ioc_reference_md = _build_ioc_reference()
        ioc_reference_data = _build_ioc_reference_data()

        @mcp.resource("crowdsentinel://data-sources")
        def get_data_sources():
            """
            Overview of all data sources available in CrowdSentinel.

            Read this resource to understand what data sources are configured,
            what each provides, and the investigation decision matrix for
            choosing which source to query first.
            """
            return DATA_SOURCES

        @mcp.resource("crowdsentinel://ioc-reference")
        def get_ioc_reference():
            """
            IoC type reference ordered by Pyramid of Pain priority.

            Read this resource to understand which IoC types matter most
            for detection. Higher priority = harder for attacker to change =
            more valuable to hunt. Includes MITRE ATT&CK event ID mappings.
            """
            return ioc_reference_md

        @mcp.resource("crowdsentinel://ioc-reference/data")
        def get_ioc_reference_data():
            """
            Machine-readable IoC reference data for programmatic use.

            Returns a dict with:
            - pyramid_of_pain: IoC type -> priority and level
            - mitre_event_mapping: Event ID -> MITRE technique/tactic
            - ioc_types: All supported IoC type values
            - source_types: All supported data source types
            """
            return ioc_reference_data

        @mcp.resource("crowdsentinel://cross-correlation-playbooks")
        def get_cross_correlation_playbooks():
            """
            Investigation playbooks for cross-correlating SIEM and endpoint data.

            Read this resource for step-by-step workflows that pivot between
            data sources (Elasticsearch, Velociraptor, Chainsaw, Wireshark)
            to conduct complete investigations. Includes 5 playbooks covering
            suspicious processes, brute force, lateral movement, persistence,
            and data exfiltration scenarios.
            """
            return CROSS_CORRELATION_PLAYBOOKS
