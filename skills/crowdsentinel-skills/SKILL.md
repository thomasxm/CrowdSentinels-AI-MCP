---
name: crowdsentinel-skills
description: Comprehensive threat hunting and incident response skill for CrowdSentinel MCP Server. Provides decision frameworks (MITRE ATT&CK, NIST IR, Pyramid of Pain, Diamond Model), workflow guidance, executable scripts for Elasticsearch queries, field mapping assistance, and debugging tools.
---

# CrowdSentinel Skills - Threat Hunting & Incident Response

## When to Use This Skill

Use this skill when:
- Conducting threat hunting on Elasticsearch/OpenSearch logs
- Running detection rules (EQL, ES|QL, Lucene)
- Investigating security incidents
- Analysing Windows/Linux logs for threats
- Debugging Elasticsearch connection issues
- Handling field mapping mismatches (non-ECS data)
- Presenting investigation findings to users

---

## The Iron Law

```
┌─────────────────────────────────────────────────────────────────────┐
│   NO INVESTIGATION IS COMPLETE WITHOUT ANALYSIS TOOLS               │
│                                                                     │
│   If you have collected data but haven't used analysis tools,       │
│   the investigation is INCOMPLETE.                                  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Decision Tree: What Should I Do?

```
START: User Request
    │
    ├─→ "Hunt for threats" / "Find suspicious activity"
    │       └─→ Go to: THREAT HUNTING WORKFLOW
    │
    ├─→ "Run detection rule" / "Execute rule"
    │       └─→ Go to: DETECTION RULE WORKFLOW
    │
    ├─→ "Investigate incident" / "Analyse this host"
    │       └─→ Go to: INCIDENT RESPONSE WORKFLOW
    │
    ├─→ "Connection error" / "Query failed"
    │       └─→ Go to: DEBUGGING WORKFLOW
    │
    ├─→ "Field not found" / "Query returns empty"
    │       └─→ Go to: FIELD MAPPING WORKFLOW
    │
    └─→ "Analyse PCAP" / "Network traffic"
            └─→ Go to: WIRESHARK WORKFLOW (see wireshark-mcp-ir-th skill)
```

---

## THREAT HUNTING WORKFLOW

### Phase 1: Data Collection

| Tool | When to Use | Token Efficiency |
|------|-------------|------------------|
| `threat_hunt_search` | IR-focused search with auto IoC extraction | High (PREFERRED) |
| `smart_search` | Quick counts and summarisation | Very High |
| `execute_detection_rule` | Run curated EQL/Lucene rules | Medium |
| `execute_esql_hunt` | Run curated ES|QL hunting queries | Medium |
| `esql_query` | Ad-hoc ES|QL queries | Low |
| `eql_search` | Ad-hoc EQL queries | Low |
| `search_with_lucene` | Flexible Lucene queries | Low |

**Decision: Which search tool?**

```
Is this an initial triage?
    │
    ├─→ YES: Use smart_search or quick_count first
    │         └─→ Then threat_hunt_search for details
    │
    └─→ NO: Do you need specific detection logic?
            │
            ├─→ YES: Use execute_detection_rule or execute_esql_hunt
            │
            └─→ NO: Use threat_hunt_search (auto IoC extraction)
```

### Phase 2: Analysis (MANDATORY - NEVER SKIP)

After EVERY search/hunt query, you MUST use analysis tools:

```python
# Step 1: Analyse search results
analysis = analyze_search_results(
    search_results=results,
    context="Description of what you searched for"
)
# Returns: IoCs, MITRE ATT&CK mapping, severity, recommendations

# Step 2: Position in kill chain
kill_chain = analyze_kill_chain_stage(
    iocs=[{"type": "ip", "value": "..."}, {"type": "process", "value": "..."}],
    include_hunting_suggestions=True
)
# Returns: Kill chain stage, previous/next stage hunting queries
```

### Phase 3: Investigation State (Multi-Query)

For investigations spanning multiple queries:

```python
# Start tracking
create_investigation(
    name="Suspicious PowerShell Activity",
    description="Investigating encoded commands on DESKTOP-001",
    severity="high"
)

# Store discovered IoCs
add_iocs_to_investigation(iocs=[...])

# Retrieve for cross-correlation
shared_iocs = get_shared_iocs(ioc_types=["ip", "domain"])
```

### Phase 4: Reporting (BEFORE Concluding)

```python
report = generate_investigation_report(
    analysis_results=[analysis1, analysis2, ...],
    investigation_context="Summary of investigation"
)
# Returns: Executive summary, all IoCs, affected hosts, recommendations
```

---

## DETECTION RULE WORKFLOW

### Decision: Which rule type?

```
What log source are you hunting in?
    │
    ├─→ Windows Event Logs (winlogbeat-*, logs-windows.*)
    │       │
    │       └─→ What behaviour are you detecting?
    │               │
    │               ├─→ Sequences/Correlations → Use EQL rules
    │               │       execute_detection_rule(rule_id="..._eql", index="winlogbeat-*")
    │               │
    │               └─→ Single events → Use Lucene rules
    │                       execute_detection_rule(rule_id="..._lucene", index="winlogbeat-*")
    │
    ├─→ Linux Audit Logs (auditbeat-*, logs-linux.*)
    │       └─→ Use ES|QL hunts or Lucene rules
    │               execute_esql_hunt(rule_id="...", index="auditbeat-*")
    │
    └─→ Network Logs (packetbeat-*, logs-network.*)
            └─→ Use Lucene rules or smart_search
```

### Finding Rules

```python
# List rules by platform and tactic
rules = list_detection_rules(
    platform="windows",
    mitre_tactic="credential_access",
    limit=20
)

# Search by keyword
rules = list_detection_rules(search_term="mimikatz")

# Get rule details before execution
details = get_rule_details(rule_id="windows_powershell_...")
```

### Executing Rules

```python
# Execute single rule
result = execute_detection_rule(
    rule_id="windows_builtin_win_security_susp_logon_eql",
    index="winlogbeat-*",
    timeframe_minutes=60
)

# Execute multiple rules (batch hunt)
results = execute_multiple_rules(
    rule_ids=["rule1", "rule2", "rule3"],
    index="winlogbeat-*",
    timeframe_minutes=1440
)

# Hunt by category
results = hunt_with_rule_category(
    platform="windows",
    category="powershell",
    index="winlogbeat-*",
    timeframe_minutes=60
)
```

---

## INCIDENT RESPONSE WORKFLOW

### NIST IR Framework Integration

```
┌──────────────────────────────────────────────────────────────────────┐
│                     NIST IR LIFECYCLE                                │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  1. PREPARATION          │  Create investigation, set severity       │
│     └─→ create_investigation(name, severity)                         │
│                                                                      │
│  2. DETECTION            │  Run detection rules, threat hunts        │
│     └─→ execute_detection_rule(), threat_hunt_search()               │
│                                                                      │
│  3. ANALYSIS             │  Analyse results, map kill chain          │
│     └─→ analyze_search_results(), analyze_kill_chain_stage()         │
│                                                                      │
│  4. CONTAINMENT          │  Identify scope, affected hosts           │
│     └─→ get_host_activity_timeline(), hunt_for_ioc()                 │
│                                                                      │
│  5. ERADICATION          │  Track IoCs for removal                   │
│     └─→ export_iocs(format="values"), add_iocs_to_investigation()    │
│                                                                      │
│  6. RECOVERY             │  Generate report for stakeholders         │
│     └─→ generate_investigation_report()                              │
│                                                                      │
│  7. LESSONS LEARNED      │  Document findings                        │
│     └─→ close_investigation(resolution="...")                        │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### Pyramid of Pain: IoC Prioritisation

```
                    ┌───────────┐
                    │   TTPs    │ ← HIGHEST VALUE: Behaviours (hunt_by_kill_chain_stage)
                   ┌┴───────────┴┐
                   │    Tools    │ ← Tool names, filenames (hunt_for_ioc type="process")
                  ┌┴─────────────┴┐
                  │  Artifacts    │ ← Registry keys, mutexes (analyze_search_results)
                 ┌┴───────────────┴┐
                 │    Domains     │ ← Domain names (hunt_for_ioc type="domain")
                ┌┴─────────────────┴┐
                │   IP Addresses   │ ← IPs (hunt_for_ioc type="ip")
               ┌┴───────────────────┴┐
               │    Hash Values     │ ← File hashes (hunt_for_ioc type="hash")
               └─────────────────────┘
                   LOWEST VALUE
```

**Tool selection by IoC type:**

| IoC Type | CrowdSentinel Tool | Priority |
|----------|-------------------|----------|
| Hash | `hunt_for_ioc(ioc_type="hash")` | 1 (Trivial) |
| IP | `hunt_for_ioc(ioc_type="ip")` | 2 (Easy) |
| Domain | `hunt_for_ioc(ioc_type="domain")` | 3 (Simple) |
| Artifact | `analyze_search_results` → extract | 4 (Annoying) |
| Tool | `hunt_for_ioc(ioc_type="process")` | 5 (Challenging) |
| TTP | `hunt_by_kill_chain_stage`, `execute_detection_rule` | 6 (Tough) |

### Diamond Model Analysis

```
                        ADVERSARY
                           │
              (Who is attacking?)
              analyze_kill_chain_stage()
                           │
         ┌─────────────────┼─────────────────┐
         │                 │                 │
    CAPABILITY ───────────┼─────────── INFRASTRUCTURE
         │                 │                 │
   (What tools?)           │           (What IPs/Domains?)
   hunt_for_ioc()          │           hunt_for_ioc()
   (type="process")        │           (type="ip/domain")
         │                 │                 │
         └─────────────────┼─────────────────┘
                           │
                        VICTIM
                           │
              (Who is targeted?)
              get_host_activity_timeline()
```

### Kill Chain Hunting

```python
# Hunt specific kill chain stage
results = hunt_by_kill_chain_stage(
    index="winlogbeat-*",
    stage="INSTALLATION",  # or RECONNAISSANCE, DELIVERY, EXPLOITATION, etc.
    timeframe_minutes=1440
)

# Hunt adjacent stages (before and after)
results = hunt_adjacent_stages(
    index="winlogbeat-*",
    current_stage="COMMAND_AND_CONTROL",
    hunt_previous=True,  # Find how they persisted
    hunt_next=True       # Find what actions they took
)

# Analyse IoCs against kill chain
analysis = analyze_kill_chain_stage(
    iocs=[
        {"type": "ip", "value": "203.0.113.42"},
        {"type": "process", "value": "mimikatz.exe"}
    ],
    include_hunting_suggestions=True
)
```

---

## DEBUGGING WORKFLOW

### Connection Issues

```
Query failed or empty results?
    │
    ├─→ "Connection refused" / "Timeout"
    │       └─→ Run: scripts/debugging/check_connection.sh
    │
    ├─→ "Authentication failed" / "401"
    │       └─→ Run: scripts/debugging/check_auth.py
    │
    ├─→ "Index not found" / "404"
    │       └─→ Run: scripts/debugging/list_indices.sh
    │
    └─→ "Empty results but index exists"
            └─→ Go to: FIELD MAPPING WORKFLOW
```

### Quick Diagnostic Commands

```bash
# Check cluster health
curl -k -u "$ES_USER:$ES_PASS" "$ES_HOST/_cluster/health?pretty"

# List all indices with document counts
curl -k -u "$ES_USER:$ES_PASS" "$ES_HOST/_cat/indices?v&s=docs.count:desc"

# Check index mapping
curl -k -u "$ES_USER:$ES_PASS" "$ES_HOST/winlogbeat-*/_mapping?pretty"

# Test simple query
curl -k -u "$ES_USER:$ES_PASS" "$ES_HOST/winlogbeat-*/_count"
```

### Using MCP Tools for Debugging

```python
# Check cluster health
health = get_cluster_health()

# List indices
indices = list_indices()

# Get index details
details = get_index(index="winlogbeat-*")

# Discover all assets
assets = discover_all_assets()
```

---

## FIELD MAPPING WORKFLOW

### The Problem

Detection rules use ECS field names, but your data may use different schemas:

| ECS Field | Winlogbeat/Sysmon | Windows Security |
|-----------|-------------------|------------------|
| `process.name` | `winlog.event_data.Image` | `winlog.event_data.NewProcessName` |
| `process.command_line` | `winlog.event_data.CommandLine` | `winlog.event_data.CommandLine` |
| `user.name` | `winlog.event_data.User` | `winlog.event_data.TargetUserName` |
| `source.ip` | `winlog.event_data.SourceIp` | `winlog.event_data.IpAddress` |

### Decision Tree

```
Query returns empty but data exists?
    │
    └─→ Step 1: Detect your schema
            │
            └─→ detect_schema_for_index(index_pattern="winlogbeat-*")
                    │
                    └─→ Returns: "sysmon", "ecs", or "windows_security"
                            │
                            └─→ Step 2: Get correct field mapping
                                    │
                                    └─→ get_field_mapping(
                                            semantic_field="source_process",
                                            event_type="process_create",
                                            schema_id="sysmon"
                                        )
                                            │
                                            └─→ Returns: "winlog.event_data.Image"
```

### Schema-Aware Hunting

```python
# Let tools auto-detect schema
results = hunt_suspicious_process_activity(
    process_name="mimikatz.exe",
    schema_hint="sysmon"  # or "ecs", "windows_security"
)

# Manual schema detection
schema = detect_schema_for_index(index_pattern="winlogbeat-*")
# Returns: {"detected_schema": "sysmon", "confidence": 0.95, ...}

# Get field mapping for your schema
field = get_field_mapping(
    semantic_field="command_line",
    event_type="process_create",
    schema_id=schema["detected_schema"]
)
# Returns: {"field": "winlog.event_data.CommandLine", ...}
```

### Manual Field Discovery

```bash
# Sample documents to see actual field names
curl -k -u "$ES_USER:$ES_PASS" "$ES_HOST/winlogbeat-*/_search?size=1&pretty"

# Get all fields in index
curl -k -u "$ES_USER:$ES_PASS" "$ES_HOST/winlogbeat-*/_mapping/field/*?pretty"
```

---

## MITRE ATT&CK Integration

### Search by Tactic

```python
# Find rules for specific tactic
rules = search_rules_by_mitre_attack(
    tactic="credential_access",
    platform="windows"
)

# Tactics available:
# - initial_access, execution, persistence, privilege_escalation
# - defense_evasion, credential_access, discovery, lateral_movement
# - collection, command_and_control, exfiltration, impact
```

### Mapping Findings to ATT&CK

```python
# analyze_search_results automatically maps to MITRE
analysis = analyze_search_results(
    search_results=results,
    context="PowerShell encoded command execution"
)
# Returns includes: mitre_techniques: ["T1059.001", "T1027"]

# Kill chain analysis also maps to ATT&CK
kill_chain = analyze_kill_chain_stage(iocs=[...])
# Returns includes: mitre_mapping for each stage
```

---

## Red Flags - Stop If You're Doing This

| If You're Thinking... | You Must... |
|-----------------------|-------------|
| "I'll just summarise the results myself" | Use `analyze_search_results` instead |
| "I can see the IoCs, no need for tools" | Use `analyze_kill_chain_stage` to position them |
| "The user just wants quick results" | Quick != incomplete. Use analysis tools. |
| "This is a simple query, no analysis needed" | ALL queries benefit from analysis tools |
| "I'll present findings now" | Use `generate_investigation_report` first |
| "The query is empty, nothing to do" | Check field mapping with `detect_schema_for_index` |
| "Connection failed, can't proceed" | Run debugging scripts first |

---

## Verification Checklist

Before presenting findings, verify:

- [ ] Used `analyze_search_results` on query results
- [ ] Used `analyze_kill_chain_stage` on extracted IoCs
- [ ] MITRE ATT&CK techniques identified
- [ ] Kill chain position determined
- [ ] If multi-query: used `create_investigation` and `add_iocs_to_investigation`
- [ ] `generate_investigation_report` called (for formal investigations)
- [ ] Recommendations included in response
- [ ] Field mapping verified if results were unexpected

---

## Quick Reference Tables

### Tool Selection by Task

| Task | Primary Tool | Alternative |
|------|-------------|-------------|
| Initial triage | `smart_search` | `quick_count` |
| Threat hunting | `threat_hunt_search` | `hunt_by_timeframe` |
| Run detection rule | `execute_detection_rule` | `execute_esql_hunt` |
| IoC search | `hunt_for_ioc` | `search_with_lucene` |
| Host investigation | `get_host_activity_timeline` | `quick_triage` |
| Kill chain hunting | `hunt_by_kill_chain_stage` | `hunt_adjacent_stages` |
| Analyse results | `analyze_search_results` | N/A (mandatory) |
| Kill chain mapping | `analyze_kill_chain_stage` | `map_events_to_kill_chain` |
| Generate report | `generate_investigation_report` | N/A |

### Timeframe Parameters

| Scenario | Recommended Timeframe |
|----------|----------------------|
| Active incident | `timeframe_minutes=60` (1 hour) |
| Daily hunt | `timeframe_minutes=1440` (24 hours) |
| Weekly review | `timeframe_days=7` |
| Historical investigation | `start_time="2024-01-01"`, `end_time="2024-01-02"` |

### Severity Levels

| Severity | When to Use | Actions |
|----------|-------------|---------|
| `critical` | Active breach, ransomware | Immediate escalation |
| `high` | Confirmed malicious activity | Urgent investigation |
| `medium` | Suspicious behaviour | Scheduled investigation |
| `low` | Minor anomaly | Log for tracking |
| `info` | Baseline/normal activity | No action required |

---

## Scripts Reference

All scripts are located in `scripts/` directory:

| Script | Purpose | Usage |
|--------|---------|-------|
| `scripts/elasticsearch/eql_search.sh` | Execute EQL via curl | `./eql_search.sh "process where process.name == 'cmd.exe'"` |
| `scripts/elasticsearch/eql_search.py` | Execute EQL via Python | `python eql_search.py --query "..."` |
| `scripts/elasticsearch/esql_search.sh` | Execute ES|QL via curl | `./esql_search.sh "FROM logs-* \| LIMIT 10"` |
| `scripts/elasticsearch/esql_search.py` | Execute ES|QL via Python | `python esql_search.py --query "..."` |
| `scripts/debugging/check_connection.sh` | Test ES connection | `./check_connection.sh` |
| `scripts/debugging/check_auth.py` | Verify authentication | `python check_auth.py` |
| `scripts/debugging/list_indices.sh` | List all indices | `./list_indices.sh` |
| `scripts/field_mapping/detect_schema.py` | Detect data schema | `python detect_schema.py --index "winlogbeat-*"` |
| `scripts/field_mapping/suggest_fields.py` | Suggest field mappings | `python suggest_fields.py --field "process.name"` |
| `scripts/field_mapping/transform_query.py` | Transform queries between schemas | `python transform_query.py --query "..." --from ecs --to sysmon` |

All Python scripts support `--output/-o json|table|summary` and follow consistent exit codes:
- `0` = success, `1` = error, `2` = no results.

All shell scripts support `-h|--help` for usage information.

---

## CLI Commands (via `crowdsentinel` CLI)

The `crowdsentinel` CLI provides the same capabilities as MCP tools from the command line.
Install via: `uv pip install crowdsentinel-mcp-server`

| MCP Tool | CLI Command | Example |
|----------|-------------|---------|
| `threat_hunt_search` | `crowdsentinel hunt` | `crowdsentinel hunt "powershell" -i winlogbeat-*` |
| `execute_detection_rule` | `crowdsentinel detect` | `crowdsentinel detect win_susp_logon -i winlogbeat-*` |
| `eql_search` | `crowdsentinel eql` | `crowdsentinel eql "process where process.name == 'cmd.exe'" -i winlogbeat-*` |
| `esql_query` | `crowdsentinel esql` | `crowdsentinel esql "FROM logs-* | LIMIT 10"` |
| `list_detection_rules` | `crowdsentinel rules` | `crowdsentinel rules -p windows --tactic credential_access` |
| `detect_schema_for_index` | `crowdsentinel schema` | `crowdsentinel schema -i winlogbeat-*` |
| `hunt_for_ioc` | `crowdsentinel ioc` | `crowdsentinel ioc 203.0.113.42 --type ip -i winlogbeat-*` |
| `get_cluster_health` | `crowdsentinel health` | `crowdsentinel health` |
| `list_indices` | `crowdsentinel indices` | `crowdsentinel indices` |
| `analyze_search_results` | `crowdsentinel analyse` | `cat results.json \| crowdsentinel analyse -c "PowerShell hunt"` |

### Pipeline Example

```bash
# Hunt then analyse (CLI equivalent of MCP workflow)
crowdsentinel hunt "powershell encoded" -i winlogbeat-* -o json | \
  crowdsentinel analyse -c "Encoded PowerShell commands" -o summary
```

---

## References

See `references/` directory for:
- `mitre_attack_reference.md` - MITRE ATT&CK tactics and techniques
- `nist_ir_reference.md` - NIST IR lifecycle details
- `pyramid_of_pain_reference.md` - IoC prioritisation guide
- `diamond_model_reference.md` - Intrusion analysis framework
- `field_mapping_reference.md` - Common field mappings across schemas
