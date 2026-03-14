# Threat Hunting & Incident Response Guide

## Overview

This Elasticsearch MCP server now includes advanced threat hunting and incident response capabilities designed to help security analysts and AI agents investigate security incidents, hunt for threats, and perform forensic analysis on security logs.

## Table of Contents

1. [New Features Overview](#new-features-overview)
2. [Asset Discovery](#asset-discovery)
3. [Threat Hunting Tools](#threat-hunting-tools)
4. [EQL Query Support](#eql-query-support)
5. [IoC Analysis & Decision Making](#ioc-analysis--decision-making)
6. [Complete Investigation Workflows](#complete-investigation-workflows)
7. [MITRE ATT&CK Integration](#mitre-attck-integration)
8. [Pyramid of Pain](#pyramid-of-pain)
9. [Example Scenarios](#example-scenarios)

---

## New Features Overview

### What's New

The server now includes **4 new tool classes** with **18 new tools** for threat hunting and incident response:

1. **AssetDiscoveryTools** (4 tools) - Discover and catalogue security assets
2. **EQLQueryTools** (3 tools) - Event Query Language for advanced hunting
3. **ThreatHuntingTools** (6 tools) - Automated threat detection and hunting
4. **IoCAnalysisTools** (2 tools) - Intelligent IoC analysis and decision making

### Key Capabilities

- **Automated Asset Discovery**: Automatically discover and catalogue all indices, determine OS types, log sources
- **Intelligent Threat Hunting**: Pre-built queries for common attack patterns (brute force, lateral movement, privilege escalation, etc.)
- **IoC Extraction & Prioritisation**: Automatically extract IoCs and prioritise them using Pyramid of Pain
- **MITRE ATT&CK Mapping**: Automatically map detected activity to MITRE ATT&CK techniques
- **Decision Logic**: AI-powered analysis that recommends follow-up queries
- **Forensic Timeline Analysis**: Build complete timelines of host activity
- **Investigation Reports**: Generate comprehensive incident response reports

---

## Asset Discovery

### Purpose

Before hunting for threats, you need to know what assets you have. Asset discovery automatically scans your Elasticsearch cluster and creates a catalogue of all security log indices with metadata.

### Tools

#### 1. `discover_all_assets()`

**Purpose**: Scan the entire Elasticsearch cluster and catalogue all indices with detailed metadata.

**What it discovers**:
- All indices (excluding system indices)
- OS type (Windows, Linux, unknown)
- Log source (Windows Event Logs, Syslog, etc.)
- Beat type (Winlogbeat, Filebeat, etc.)
- Field mappings and structure
- Index patterns for quick reference

**Output**: Saves to `assets/discovered_assets.json`

**Example**:
```python
# Discover all assets
assets = discover_all_assets()

# Result structure:
{
  "discovery_timestamp": "2024-12-20T10:00:00Z",
  "cluster_name": "production-cluster",
  "indices": [
    {
      "name": "winlogbeat-2024.12.20",
      "health": "green",
      "doc_count": "150000",
      "metadata": {
        "os_type": "windows",
        "log_source": "Windows Event Logs",
        "beat_type": "winlogbeat",
        "log_type": "Windows Security Logs",
        "has_ecs": true,
        "fields": ["@timestamp", "event.code", "user.name", ...]
      }
    }
  ],
  "index_patterns": {
    "windows_security": ["winlogbeat-*"],
    "linux_syslog": ["filebeat-linux-*"],
    ...
  }
}
```

#### 2. `get_saved_assets()`

**Purpose**: Retrieve previously discovered assets from file.

**Use case**: Quick reference without re-scanning

#### 3. `get_indices_by_type(log_type: str)`

**Purpose**: Get all indices matching a specific type.

**Examples**:
```python
# Get all Windows indices
windows_indices = get_indices_by_type("windows")
# Returns: ["winlogbeat-2024.12.20", "winlogbeat-2024.12.19", ...]

# Get all Linux indices
linux_indices = get_indices_by_type("linux")

# Get Sysmon logs
sysmon_indices = get_indices_by_type("sysmon")
```

#### 4. `get_index_metadata(index_pattern: str)`

**Purpose**: Get detailed metadata for a specific index.

**Example**:
```python
metadata = get_index_metadata("winlogbeat-*")
# Returns OS type, log source, fields available, etc.
```

### Workflow: Asset Discovery

```
Step 1: discover_all_assets()
   ↓
Step 2: Review discovered_assets.json
   ↓
Step 3: Use get_indices_by_type() to find relevant indices
   ↓
Step 4: Begin threat hunting with the correct index patterns
```

---

## Threat Hunting Tools

### Pre-Built Attack Pattern Detection

The server includes pre-configured detection logic for 8 common attack patterns based on Windows Security Event IDs.

### Attack Patterns Supported

| Pattern | Description | Event IDs | Use Case |
|---------|-------------|-----------|----------|
| **brute_force** | Failed login attempts | 4625, 4776 | Detect password guessing attacks |
| **privilege_escalation** | Privilege escalation attempts | 4672, 4673, 4674 | Detect privilege abuse |
| **lateral_movement** | Movement between systems | 4624, 4648, 4672 | Track attacker spread |
| **persistence** | Persistence mechanisms | 4697, 4698, 4720, 4732 | Find backdoors |
| **suspicious_process** | Suspicious process execution | 4688 | Detect LOLBins usage |
| **encoded_commands** | Encoded PowerShell | 4688 | Find obfuscated commands |
| **credential_access** | Credential dumping | 4688, 4656 | Detect credential theft |
| **port_scan** | Port scanning activity | Network events | Find reconnaissance |

### Tools

#### 1. `hunt_by_timeframe()`

**Purpose**: Hunt for multiple attack patterns within a time window.

**Parameters**:
- `index`: Index pattern (e.g., "winlogbeat-*")
- `attack_types`: List of attack patterns to hunt for
- `start_time`: When to start searching (e.g., "now-15m", "2024-12-20T10:00:00")
- `end_time`: When to stop (optional, defaults to "now")
- `host`: Specific host to investigate (optional)

**Example**:
```python
# User asks: "Please check if any suspicious attacks happened in the last 15 mins"

# AI Agent workflow:
# 1. Ask user for OS type
user_response = ask_user("Windows or Linux target?")  # User says: "Windows"

# 2. Get appropriate indices
indices = get_indices_by_type("windows")  # Returns: "winlogbeat-*"

# 3. Hunt for common attack patterns
results = hunt_by_timeframe(
    index="winlogbeat-*",
    attack_types=["brute_force", "privilege_escalation", "suspicious_process", "lateral_movement"],
    start_time="now-15m"
)

# Results structure:
{
  "search_timeframe": {"start": "now-15m", "end": "now"},
  "attack_patterns": {
    "brute_force": {
      "description": "Brute force authentication attempts",
      "total_hits": 47,
      "events": [...]
    },
    "suspicious_process": {
      "description": "Suspicious process execution",
      "total_hits": 3,
      "events": [...]
    }
  }
}
```

#### 2. `analyze_failed_logins()`

**Purpose**: Deep dive into failed login attempts to detect brute force attacks.

**Parameters**:
- `index`: Index pattern
- `timeframe_minutes`: Time window (default: 15)
- `threshold`: Minimum failed attempts to flag (default: 5)

**What it finds**:
- Users with multiple failed logins
- Hosts with multiple failed logins
- Source IPs attempting authentication

**Example**:
```python
# Detect brute force
analysis = analyze_failed_logins(
    index="winlogbeat-*",
    timeframe_minutes=15,
    threshold=5
)

# Results:
{
  "total_failed_logins": 47,
  "suspicious_users": [
    {
      "key": "admin",
      "doc_count": 25,
      "by_source_ip": [
        {"key": "192.168.1.100", "doc_count": 25}
      ]
    }
  ],
  "suspicious_hosts": [...]
}
```

#### 3. `analyze_process_creation()`

**Purpose**: Analyse process creation events for suspicious activity.

**Parameters**:
- `index`: Index pattern
- `timeframe_minutes`: Time window (default: 60)
- `process_filter`: List of specific processes to find (optional)

**Example**:
```python
# Find all PowerShell execution
results = analyze_process_creation(
    index="winlogbeat-*",
    timeframe_minutes=60,
    process_filter=["powershell.exe", "cmd.exe", "mshta.exe"]
)

# Returns:
{
  "total_processes": 15,
  "processes": [
    {
      "_source": {
        "@timestamp": "2024-12-20T10:30:00Z",
        "host.name": "WS001",
        "user.name": "admin",
        "winlog.event_data.NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "winlog.event_data.CommandLine": "powershell.exe -encodedCommand <base64>",
        "winlog.event_data.ParentProcessName": "C:\\Windows\\System32\\cmd.exe"
      }
    }
  ]
}
```

#### 4. `hunt_for_ioc()`

**Purpose**: Hunt for specific Indicators of Compromise across all logs.

**Parameters**:
- `index`: Index pattern
- `ioc`: The IoC value
- `ioc_type`: Type (ip, domain, hash, filename, process, user)
- `timeframe_minutes`: Optional time limit

**IoC Types Supported**:
- **ip**: Searches source.ip, destination.ip, client.ip
- **domain**: Searches dns.question.name, url.domain
- **hash**: Searches file.hash.md5, file.hash.sha256
- **filename**: Searches file.name, file.path
- **process**: Searches process.name, winlog.event_data.NewProcessName
- **user**: Searches user.name

**Example**:
```python
# Hunt for malicious executable
results = hunt_for_ioc(
    index="winlogbeat-*",
    ioc="malicious.exe",
    ioc_type="filename",
    timeframe_minutes=1440  # Last 24 hours
)

# Returns all events containing that filename
{
  "ioc": "malicious.exe",
  "ioc_type": "filename",
  "total_hits": 5,
  "events": [...]
}
```

#### 5. `get_host_activity_timeline()`

**Purpose**: Get complete forensic timeline for a specific host.

**Parameters**:
- `index`: Index pattern
- `hostname`: Host to investigate
- `start_time`: Timeline start
- `end_time`: Timeline end (optional)

**Use case**: Forensic analysis, incident scope determination

**Example**:
```python
# User asks: "What processes are running on agent 001?"

# Get complete timeline
timeline = get_host_activity_timeline(
    index="winlogbeat-*",
    hostname="agent-001",
    start_time="now-1h"
)

# Returns chronological timeline of all events
{
  "hostname": "agent-001",
  "timeframe": {"start": "now-1h", "end": "now"},
  "total_events": 250,
  "timeline": [
    {
      "@timestamp": "2024-12-20T09:00:00Z",
      "event.code": "4624",
      "event.action": "logon",
      "user.name": "john.doe"
    },
    {
      "@timestamp": "2024-12-20T09:05:00Z",
      "event.code": "4688",
      "winlog.event_data.NewProcessName": "powershell.exe",
      "winlog.event_data.CommandLine": "..."
    }
  ]
}
```

#### 6. `search_with_lucene()`

**Purpose**: Execute custom Lucene query strings for flexible hunting.

**Parameters**:
- `index`: Index pattern
- `lucene_query`: Lucene query syntax
- `timeframe_minutes`: Optional time window
- `size`: Number of results (default: 100)

**Lucene Query Examples**:
```
# Find specific event with command line
"event.code:4688 AND winlog.event_data.CommandLine:*powershell*"

# Boolean operators
"event.code:(4624 OR 4625) AND user.name:admin"

# Wildcards
"process.name:*.exe AND @timestamp:[now-1h TO now]"

# Field existence
"_exists_:winlog.event_data.CommandLine"
```

**Example**:
```python
# Custom hunt query
results = search_with_lucene(
    index="winlogbeat-*",
    lucene_query="event.code:4688 AND winlog.event_data.CommandLine:(*-enc* OR *-encodedcommand*)",
    timeframe_minutes=60
)
```

---

## EQL Query Support

### What is EQL?

Event Query Language (EQL) is a query language designed specifically for event-based data. It's excellent for detecting attack patterns and sequences.

### Tools

#### 1. `eql_search()`

**Purpose**: Execute EQL queries for advanced threat detection.

**Parameters**:
- `index`: Index pattern
- `query`: EQL query string
- `size`: Max results (default: 100)
- `filter_query`: Optional pre-filter
- `timestamp_field`: Timestamp field (default: "@timestamp")

**EQL Query Examples**:

1. **Simple process query**:
```python
eql_search(
    index="winlogbeat-*",
    query='process where process.name == "regsvr32.exe"'
)
```

2. **Sequence detection** (process followed by network):
```python
eql_search(
    index="logs-*",
    query='''
    sequence
      [process where process.name == "cmd.exe"]
      [network where destination.port == 443]
    '''
)
```

3. **Registry modifications**:
```python
eql_search(
    index="sysmon-*",
    query='registry where registry.path == "*\\\\Run\\\\*"'
)
```

---

## IoC Analysis & Decision Making

### The Intelligence Layer

This is the "brain" of the threat hunting system. It analyzes search results and provides intelligent recommendations.

### Tools

#### 1. `analyze_search_results()`

**Purpose**: Analyse any search results and provide intelligent insights with follow-up recommendations.

**Parameters**:
- `search_results`: Results from any search/hunt tool
- `context`: What you were searching for

**What it does**:
1. Extracts all IoCs (IPs, users, processes, command lines, hostnames)
2. Prioritizes IoCs using Pyramid of Pain
3. Maps events to MITRE ATT&CK techniques
4. Assesses severity (critical/high/medium/low)
5. Generates human-readable insights
6. Recommends specific follow-up queries

**Pyramid of Pain Prioritisation**:
- **Priority 6 (TTPs/Behaviours)**: Focus here! Hard for attackers to change
- **Priority 5 (Tools)**: Challenging to change
- **Priority 4 (Network Artifacts)**: Annoying to change
- **Priority 3 (Domains)**: Simple to change
- **Priority 2 (IPs)**: Easy to change
- **Priority 1 (Hashes)**: Trivial to change

**Example Workflow**:
```python
# Step 1: Hunt for suspicious activity
hunt_results = hunt_by_timeframe(
    index="winlogbeat-*",
    attack_types=["brute_force", "suspicious_process"],
    start_time="now-15m"
)

# Step 2: Analyse the results
analysis = analyze_search_results(
    search_results=hunt_results,
    context="Investigating potential brute force attack"
)

# Analysis result:
{
  "timestamp": "2024-12-20T10:00:00Z",
  "context": "Investigating potential brute force attack",
  "summary": {
    "total_events": 47,
    "events_analyzed": 47,
    "status": "Suspicious activity detected"
  },
  "iocs_found": [
    {
      "type": "commandline",
      "value": "powershell.exe -encodedCommand <base64>",
      "pyramid_priority": 6,  # Highest priority - TTP
      "field": "winlog.event_data.CommandLine"
    },
    {
      "type": "user",
      "value": "admin",
      "pyramid_priority": 4,
      "field": "user.name"
    },
    {
      "type": "ip",
      "value": "192.168.1.100",
      "pyramid_priority": 2,
      "field": "source.ip"
    }
  ],
  "mitre_attack_techniques": [
    {
      "technique_id": "T1110",
      "technique_name": "Brute Force",
      "tactic": "Credential Access",
      "event_code": "4625",
      "count": 25
    },
    {
      "technique_id": "T1059",
      "technique_name": "Command and Scripting Interpreter",
      "tactic": "Execution",
      "event_code": "4688",
      "count": 3
    }
  ],
  "severity_assessment": "high",
  "raw_insights": [
    "HIGH VOLUME: Detected 47 security events, indicating significant activity",
    "SUSPICIOUS COMMAND: Detected 'encoded' in command line execution",
    "MITRE ATT&CK: Detected techniques from 2 different tactics: Credential Access, Execution",
    "REPEATED TECHNIQUE: Brute Force (T1110) occurred 25 times"
  ],
  "recommended_followup": [
    {
      "priority": "high",
      "reason": "Investigate all activity for user 'admin'",
      "tool": "get_host_activity_timeline",
      "parameters": {
        "search_scope": "all_indices",
        "ioc": "admin",
        "ioc_type": "user"
      },
      "query_description": "Search for all events involving user admin to understand scope"
    },
    {
      "priority": "high",
      "reason": "Correlate multiple IoCs to identify attack chain",
      "tool": "custom_correlation",
      "parameters": {
        "iocs": ["admin", "192.168.1.100", "powershell.exe"]
      },
      "query_description": "Build timeline showing relationship between identified IoCs"
    }
  ]
}
```

#### 2. `generate_investigation_report()`

**Purpose**: Aggregate multiple analyses into a comprehensive incident report.

**Parameters**:
- `analysis_results`: List of results from `analyze_search_results()`
- `investigation_context`: Overall investigation context

**Use case**: Final report after complete investigation

**Example**:
```python
# After running multiple queries and analyses...
final_report = generate_investigation_report(
    analysis_results=[analysis1, analysis2, analysis3],
    investigation_context="Suspected ransomware on finance workstations"
)

# Report structure:
{
  "report_id": "IR-20241220-100000",
  "generated_at": "2024-12-20T10:00:00Z",
  "investigation_context": "Suspected ransomware on finance workstations",
  "executive_summary": "SEVERITY: CRITICAL | Affected 3 host(s) | Involving 2 user account(s) | Identified: 5 user(s), 3 hostname(s), 8 commandline(s) | MITRE ATT&CK Tactics: Execution, Persistence, Credential Access",
  "total_queries_executed": 3,
  "all_iocs": [...],  # Aggregated from all analyses
  "all_techniques": [...],  # MITRE ATT&CK techniques found
  "affected_hosts": ["WS001", "WS002", "WS003"],
  "affected_users": ["john.doe", "admin"],
  "severity": "critical",
  "recommendations": [...]  # All recommended follow-ups
}
```

---

## Complete Investigation Workflows

### Scenario 1: User Reports "Suspicious Activity in Last 15 Minutes"

```
User: "Please check if any suspicious attacks happened in the last 15 mins"

AI Agent Workflow:
┌────────────────────────────────────────────────────────────┐
│ Step 1: Determine Target OS Type                          │
├────────────────────────────────────────────────────────────┤
│ AI: "Windows or Linux target?"                            │
│ User: "Windows"                                           │
└────────────────────────────────────────────────────────────┘
                            ↓
┌────────────────────────────────────────────────────────────┐
│ Step 2: Discover Assets                                   │
├────────────────────────────────────────────────────────────┤
│ indices = get_indices_by_type("windows")                  │
│ # Returns: "winlogbeat-*"                                 │
└────────────────────────────────────────────────────────────┘
                            ↓
┌────────────────────────────────────────────────────────────┐
│ Step 3: Hunt for Common Attack Patterns                   │
├────────────────────────────────────────────────────────────┤
│ results = hunt_by_timeframe(                              │
│     index="winlogbeat-*",                                 │
│     attack_types=[                                        │
│         "brute_force",                                    │
│         "privilege_escalation",                           │
│         "suspicious_process",                             │
│         "lateral_movement"                                │
│     ],                                                    │
│     start_time="now-15m"                                  │
│ )                                                         │
└────────────────────────────────────────────────────────────┘
                            ↓
┌────────────────────────────────────────────────────────────┐
│ Step 4: Analyse Results                                   │
├────────────────────────────────────────────────────────────┤
│ analysis = analyze_search_results(                        │
│     search_results=results,                               │
│     context="15-minute security sweep"                    │
│ )                                                         │
│                                                           │
│ # Extracts IoCs, maps to MITRE, assesses severity        │
└────────────────────────────────────────────────────────────┘
                            ↓
┌────────────────────────────────────────────────────────────┐
│ Step 5: Present Summary to User                           │
├────────────────────────────────────────────────────────────┤
│ AI: "Found 47 suspicious events in the last 15 minutes:  │
│                                                           │
│ Severity: HIGH                                            │
│                                                           │
│ Findings:                                                 │
│ - 25 failed login attempts for user 'admin' from IP      │
│   192.168.1.100 (MITRE T1110: Brute Force)               │
│ - 3 suspicious PowerShell executions with encoded        │
│   commands (MITRE T1059: Command and Scripting)          │
│                                                           │
│ Key IoCs (prioritized by Pyramid of Pain):               │
│ 1. [Priority 6] Encoded PowerShell commands              │
│ 2. [Priority 4] User 'admin' compromised                 │
│ 3. [Priority 2] Source IP 192.168.1.100                  │
│                                                           │
│ Would you like me to:                                     │
│ A) Investigate all activity for user 'admin'             │
│ B) Get forensic timeline for affected hosts              │
│ C) Hunt for encoded PowerShell across environment        │
└────────────────────────────────────────────────────────────┘
                            ↓
┌────────────────────────────────────────────────────────────┐
│ Step 6: User Chooses Follow-up                            │
├────────────────────────────────────────────────────────────┤
│ User: "A - investigate admin account"                    │
└────────────────────────────────────────────────────────────┘
                            ↓
┌────────────────────────────────────────────────────────────┐
│ Step 7: Follow-up Investigation                           │
├────────────────────────────────────────────────────────────┤
│ admin_activity = hunt_for_ioc(                            │
│     index="winlogbeat-*",                                 │
│     ioc="admin",                                          │
│     ioc_type="user",                                      │
│     timeframe_minutes=1440  # Last 24 hours               │
│ )                                                         │
│                                                           │
│ analysis2 = analyze_search_results(                       │
│     search_results=admin_activity,                        │
│     context="Tracking admin account activity"            │
│ )                                                         │
└────────────────────────────────────────────────────────────┘
                            ↓
┌────────────────────────────────────────────────────────────┐
│ Step 8: Continue Investigation Based on New Findings      │
├────────────────────────────────────────────────────────────┤
│ # Repeat analysis → recommendation → follow-up cycle     │
│ # Until root cause is found                               │
└────────────────────────────────────────────────────────────┘
                            ↓
┌────────────────────────────────────────────────────────────┐
│ Step 9: Generate Final Report                             │
├────────────────────────────────────────────────────────────┤
│ report = generate_investigation_report(                   │
│     analysis_results=[analysis, analysis2, analysis3],    │
│     investigation_context="Brute force investigation"    │
│ )                                                         │
│                                                           │
│ AI: Presents comprehensive report with:                   │
│ - Executive summary                                       │
│ - All IoCs discovered                                     │
│ - Affected hosts and users                                │
│ - Complete MITRE ATT&CK kill chain                        │
│ - Root cause analysis                                     │
│ - Remediation recommendations                             │
└────────────────────────────────────────────────────────────┘
```

### Scenario 2: "What processes are running on agent 001?"

```
User: "What processes are running on agent 001?"

AI Agent Workflow:
┌────────────────────────────────────────────────────────────┐
│ Step 1: Get Host Timeline                                 │
├────────────────────────────────────────────────────────────┤
│ timeline = get_host_activity_timeline(                    │
│     index="winlogbeat-*",                                 │
│     hostname="agent-001",                                 │
│     start_time="now-1h"  # Recent activity                │
│ )                                                         │
└────────────────────────────────────────────────────────────┘
                            ↓
┌────────────────────────────────────────────────────────────┐
│ Step 2: Filter for Process Creation Events                │
├────────────────────────────────────────────────────────────┤
│ processes = analyze_process_creation(                     │
│     index="winlogbeat-*",                                 │
│     timeframe_minutes=60                                  │
│ )                                                         │
│ # Filter for agent-001 from results                      │
└────────────────────────────────────────────────────────────┘
                            ↓
┌────────────────────────────────────────────────────────────┐
│ Step 3: Present Process List                              │
├────────────────────────────────────────────────────────────┤
│ AI: "Found 15 processes running on agent-001:            │
│                                                           │
│ Recent Process Activity:                                  │
│ 1. 10:30:00 - explorer.exe (user: john.doe)              │
│ 2. 10:35:00 - chrome.exe (user: john.doe)                │
│ 3. 10:40:00 - powershell.exe (user: john.doe)            │
│    Command: powershell.exe -encodedCommand <base64>      │
│    ⚠️  SUSPICIOUS: Encoded command detected               │
│ 4. 10:45:00 - cmd.exe (user: SYSTEM)                     │
│ ...                                                       │
│                                                           │
│ ⚠️  Alert: Detected suspicious PowerShell with encoded    │
│ command at 10:40:00. Would you like to investigate?      │
└────────────────────────────────────────────────────────────┘
                            ↓
┌────────────────────────────────────────────────────────────┐
│ Step 4: Automatic Threat Assessment                       │
├────────────────────────────────────────────────────────────┤
│ analysis = analyze_search_results(                        │
│     search_results=processes,                             │
│     context="Agent-001 process review"                   │
│ )                                                         │
│                                                           │
│ # If suspicious activity found, recommend investigation  │
└────────────────────────────────────────────────────────────┘
```

### Scenario 3: "Are we meeting PCI-DSS logging requirements?"

```
User: "Are we meeting PCI-DSS logging requirements?"

AI Agent Workflow:
┌────────────────────────────────────────────────────────────┐
│ Step 1: Discover All Assets                               │
├────────────────────────────────────────────────────────────┤
│ assets = discover_all_assets()                            │
│ # Check what log sources we have                          │
└────────────────────────────────────────────────────────────┘
                            ↓
┌────────────────────────────────────────────────────────────┐
│ Step 2: Check for Required PCI-DSS Events                 │
├────────────────────────────────────────────────────────────┤
│ PCI-DSS Required Events:                                  │
│ - User access to cardholder data (Event ID 4663)          │
│ - Authentication attempts (4624, 4625)                    │
│ - Privileged access (4672)                                │
│ - Account changes (4720, 4726, 4738)                      │
│ - Audit trail modifications (1102)                        │
│                                                           │
│ # Hunt for each required event type                      │
│ for event_id in pci_dss_events:                           │
│     results = search_with_lucene(                         │
│         index="winlogbeat-*",                             │
│         lucene_query=f"event.code:{event_id}",           │
│         timeframe_minutes=1440  # Last 24 hours           │
│     )                                                     │
└────────────────────────────────────────────────────────────┘
                            ↓
┌────────────────────────────────────────────────────────────┐
│ Step 3: Generate Compliance Report                        │
├────────────────────────────────────────────────────────────┤
│ AI: "PCI-DSS Logging Compliance Assessment:               │
│                                                           │
│ ✓ Authentication logging: COMPLIANT                       │
│   - 4624 (Successful logon): 1,245 events                │
│   - 4625 (Failed logon): 47 events                       │
│                                                           │
│ ✓ Privileged access logging: COMPLIANT                    │
│   - 4672 (Special privileges): 89 events                 │
│                                                           │
│ ✓ Account management: COMPLIANT                           │
│   - 4720 (User created): 2 events                        │
│   - 4726 (User deleted): 1 event                         │
│                                                           │
│ ⚠️  File access logging: PARTIAL                          │
│   - 4663 events found but < 10% of expected volume       │
│   - Recommendation: Enable file audit logging            │
│                                                           │
│ ✗ Audit trail protection: NON-COMPLIANT                   │
│   - No 1102 (Audit log cleared) monitoring detected     │
│   - Action required: Enable audit log monitoring         │
└────────────────────────────────────────────────────────────┘
```

---

## MITRE ATT&CK Integration

### Automatic Technique Mapping

The analysis tools automatically map Windows Security Events to MITRE ATT&CK techniques:

| Event ID | Technique | Tactic | Description |
|----------|-----------|--------|-------------|
| 4624 | T1078 | Defense Evasion | Valid Accounts |
| 4625 | T1110 | Credential Access | Brute Force |
| 4672 | T1078.002 | Privilege Escalation | Admin Account |
| 4688 | T1059 | Execution | Command and Scripting Interpreter |
| 4697 | T1543.003 | Persistence | Windows Service |
| 4698 | T1053.005 | Persistence | Scheduled Task |
| 4720 | T1136.001 | Persistence | Create Account |
| 4732 | T1098 | Persistence | Account Manipulation |
| 5140 | T1021.002 | Lateral Movement | SMB/Windows Admin Shares |

### Kill Chain Reconstruction

When you use `analyze_search_results()`, it automatically builds the MITRE ATT&CK kill chain:

```python
analysis = analyze_search_results(search_results, context)

# Examine the kill chain:
for technique in analysis["mitre_attack_techniques"]:
    print(f"{technique['tactic']}: {technique['technique_name']} ({technique['technique_id']})")

# Output:
# Credential Access: Brute Force (T1110)
# Execution: Command and Scripting Interpreter (T1059)
# Persistence: Scheduled Task (T1053.005)
# Lateral Movement: SMB/Windows Admin Shares (T1021.002)
```

---

## Pyramid of Pain

### IoC Prioritisation Strategy

The Pyramid of Pain guides which IoCs to investigate first:

```
                    ▲
                   ╱ ╲
                  ╱   ╲  TTPs (Priority 6)
                 ╱─────╲  ← FOCUS HERE!
                ╱       ╲  Behaviours, Command Patterns
               ╱─────────╲
              ╱   Tools   ╲ (Priority 5)
             ╱─────────────╲ Process Names, Tool Signatures
            ╱  Network/Host ╲ (Priority 4)
           ╱─────────────────╲ Network Artifacts, Certificates
          ╱     Domains       ╲ (Priority 3)
         ╱───────────────────────╲ malicious.com
        ╱     IP Addresses     ╲ (Priority 2)
       ╱─────────────────────────╲ 192.168.1.100
      ╱        Hashes             ╲ (Priority 1)
     ╱───────────────────────────────╲ MD5, SHA1, SHA256
```

### Why This Matters

- **Hash Values**: Trivial to change (recompile malware)
- **IP Addresses**: Easy to change (new VPS)
- **Domains**: Simple to change (register new domain)
- **Network Artifacts**: Annoying to change (requires infrastructure)
- **Tools**: Challenging to change (requires development)
- **TTPs**: Tough to change (fundamental attacker behaviour)

**Investigation Strategy**: Start with high-priority IoCs (TTPs, behaviours) because they reveal attacker methodology, not just individual indicators.

### Automatic Prioritisation

```python
analysis = analyze_search_results(results, context)

# IoCs are automatically sorted by pyramid_priority (highest first)
for ioc in analysis["iocs_found"]:
    print(f"[Priority {ioc['pyramid_priority']}] {ioc['type']}: {ioc['value']}")

# Output:
# [Priority 6] commandline: powershell.exe -encodedCommand <base64>
# [Priority 5] process: mimikatz.exe
# [Priority 4] user: admin
# [Priority 2] ip: 192.168.1.100
```

---

## Example Scenarios

### Full Investigation Example

```python
"""
Complete investigation workflow for:
"Suspected data exfiltration on finance workstation"
"""

# Phase 1: Asset Discovery
# ========================
print("Phase 1: Discovering assets...")
assets = discover_all_assets()
windows_indices = get_indices_by_type("windows")
print(f"Found Windows indices: {windows_indices}")

# Phase 2: Initial Threat Hunt
# =============================
print("\nPhase 2: Hunting for suspicious activity...")
hunt_results = hunt_by_timeframe(
    index=windows_indices[0],
    attack_types=[
        "suspicious_process",
        "lateral_movement",
        "credential_access"
    ],
    start_time="now-24h",
    host="finance-ws-01"
)

# Phase 3: Analyse Results
# ========================
print("\nPhase 3: Analysing results...")
analysis1 = analyze_search_results(
    search_results=hunt_results,
    context="Initial sweep for data exfiltration indicators"
)

print(f"Severity: {analysis1['severity_assessment']}")
print(f"Found {len(analysis1['iocs_found'])} IoCs")
print(f"MITRE Techniques: {len(analysis1['mitre_attack_techniques'])}")

# Phase 4: Follow High-Priority IoCs
# ===================================
print("\nPhase 4: Investigating high-priority IoCs...")
high_priority_iocs = [ioc for ioc in analysis1['iocs_found'] if ioc['pyramid_priority'] >= 5]

for ioc in high_priority_iocs[:3]:  # Top 3
    print(f"\nInvestigating: {ioc['type']} = {ioc['value']}")

    followup_results = hunt_for_ioc(
        index=windows_indices[0],
        ioc=ioc['value'],
        ioc_type=ioc['type'],
        timeframe_minutes=2880  # 48 hours
    )

    analysis2 = analyze_search_results(
        search_results=followup_results,
        context=f"Tracking IoC: {ioc['value']}"
    )

    print(f"  Found {analysis2['summary']['total_events']} related events")

# Phase 5: Forensic Timeline
# ===========================
print("\nPhase 5: Building forensic timeline...")
timeline = get_host_activity_timeline(
    index=windows_indices[0],
    hostname="finance-ws-01",
    start_time="now-48h"
)

print(f"Timeline contains {timeline['total_events']} events")

# Phase 6: Generate Final Report
# ===============================
print("\nPhase 6: Generating investigation report...")
final_report = generate_investigation_report(
    analysis_results=[analysis1, analysis2],
    investigation_context="Suspected data exfiltration on finance workstation"
)

print("\n" + "="*60)
print("INVESTIGATION REPORT")
print("="*60)
print(f"Report ID: {final_report['report_id']}")
print(f"Severity: {final_report['severity']}")
print(f"\nExecutive Summary:")
print(final_report['executive_summary'])
print(f"\nAffected Hosts: {final_report['affected_hosts']}")
print(f"Affected Users: {final_report['affected_users']}")
print(f"\nTotal IoCs Found: {len(final_report['all_iocs'])}")
print(f"MITRE ATT&CK Techniques: {len(final_report['all_techniques'])}")
print("\n" + "="*60)
```

---

## Best Practices

### 1. Always Start with Asset Discovery
```python
# Before hunting, know your assets
assets = discover_all_assets()
```

### 2. Use Analyse After Every Hunt
```python
# Don't just look at raw results
results = hunt_by_timeframe(...)
analysis = analyze_search_results(results, context="...")  # Get insights!
```

### 3. Follow the Pyramid of Pain
```python
# Prioritize high-value IoCs
for ioc in analysis['iocs_found']:
    if ioc['pyramid_priority'] >= 5:  # TTPs and Tools
        # Investigate these first!
```

### 4. Map to MITRE ATT&CK
```python
# Understand attacker tactics
for technique in analysis['mitre_attack_techniques']:
    print(f"Detected: {technique['tactic']} - {technique['technique_name']}")
```

### 5. Build Complete Timelines
```python
# For forensic analysis, get the full picture
timeline = get_host_activity_timeline(
    index="winlogbeat-*",
    hostname="compromised-host",
    start_time="now-7d"  # Go back far enough
)
```

### 6. Generate Reports
```python
# Document your investigation
report = generate_investigation_report(
    analysis_results=[analysis1, analysis2, analysis3],
    investigation_context="Complete investigation summary"
)
```

---

## Security & Compliance

### Read-Only Access

All threat hunting tools are **read-only**. They cannot:
- Modify logs
- Delete events
- Change indices
- Write data

### Guardrails

The MCP server enforces:
- No write operations to log indices
- No deletion of security events  - All queries are audited via logging
- High-risk operations remain disabled

---

## Troubleshooting

### Common Issues

#### No results found

```python
# Check if assets exist
assets = get_saved_assets()
if not assets:
    discover_all_assets()  # Run discovery first
```

#### Wrong index pattern

```python
# Use asset discovery to find correct indices
indices = get_indices_by_type("windows")
print(f"Use this index: {indices}")
```

#### Too many results

```python
# Narrow timeframe
results = hunt_by_timeframe(
    index="winlogbeat-*",
    attack_types=["brute_force"],
    start_time="now-1h",  # Shorter window
    host="specific-host"  # Add host filter
)
```

---

## Summary

This enhanced Elasticsearch MCP server provides:

✅ **Automated Asset Discovery** - Know what you have
✅ **Intelligent Threat Hunting** - Pre-built attack patterns
✅ **EQL Support** - Advanced sequence detection
✅ **IoC Analysis** - Pyramid of Pain prioritisation
✅ **MITRE ATT&CK Mapping** - Understand tactics
✅ **Decision Logic** - AI-powered recommendations
✅ **Forensic Timelines** - Complete host history
✅ **Investigation Reports** - Professional documentation

**Total Tools**: 18 new tools across 4 categories
**Security**: Read-only access, no log modification
**Intelligence**: Automatic IoC extraction, MITRE mapping, severity assessment
**Workflow**: Guided investigation with follow-up recommendations

For complete API reference, see ARCHITECTURE.md.
