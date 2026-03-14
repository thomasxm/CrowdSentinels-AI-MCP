# Detection Rules System Guide

## Overview

The Elasticsearch Threat Hunting MCP Server now includes a comprehensive detection rules library with **5,000+ community detection rules** for threat hunting and incident response.

### Rule Library Statistics

- **Total Rules**: 5,048+ detection rules
- **Lucene Rules**: 1,967 rules
- **EQL Rules**: 3,081 rules
- **Platforms**: Windows, Linux, macOS, Cloud, Network, Applications
- **Coverage**: MITRE ATT&CK framework mapped

---

## New MCP Tools for Rule Management

### 1. list_detection_rules()

Browse and search the detection rule library.

**Parameters:**
- `platform` (optional): Filter by platform (windows, linux, macos, application, cloud, network)
- `log_source` (optional): Filter by log source (powershell, process_creation, builtin, audit, etc.)
- `rule_type` (optional): Filter by rule type (lucene, eql)
- `search_term` (optional): Search in rule names, tags, and descriptions
- `mitre_tactic` (optional): Filter by MITRE ATT&CK tactic
- `limit` (default: 50, max: 200): Maximum number of results

**Examples:**

```
# List Windows PowerShell rules
list_detection_rules(platform="windows", log_source="powershell")

# Find credential access rules
list_detection_rules(mitre_tactic="credential_access")

# Search for mimikatz-related rules
list_detection_rules(search_term="mimikatz")

# Get all EQL rules for Linux
list_detection_rules(platform="linux", rule_type="eql")
```

**Response:**
```json
{
  "total_found": 150,
  "showing": 50,
  "rules": [
    {
      "rule_id": "windows_powershell_posh_ps_potential_invoke_mimikatz_eql",
      "name": "Posh Ps Potential Invoke Mimikatz",
      "platform": "windows",
      "log_source": "powershell",
      "type": "eql",
      "category": "powershell_script",
      "mitre_tactics": ["credential_access"],
      "tags": ["windows", "powershell", "mimikatz", "eql"]
    }
  ],
  "available_platforms": ["windows", "linux", "macos", "application", "cloud"],
  "available_log_sources": ["powershell", "process_creation", "builtin", ...],
  "statistics": {
    "total_rules_loaded": 5048,
    "by_platform": {
      "windows": 3200,
      "linux": 850,
      "macos": 180,
      ...
    },
    "by_type": {
      "lucene": 1967,
      "eql": 3081
    }
  }
}
```

---

### 2. get_rule_details()

Get complete information about a specific rule.

**Parameters:**
- `rule_id`: The unique rule identifier (from list_detection_rules)

**Example:**
```
get_rule_details("windows_powershell_posh_ps_potential_invoke_mimikatz_eql")
```

**Response:**
```json
{
  "rule_id": "windows_powershell_posh_ps_potential_invoke_mimikatz_eql",
  "name": "Posh Ps Potential Invoke Mimikatz",
  "platform": "windows",
  "log_source": "powershell",
  "category": "powershell_script",
  "type": "eql",
  "query": "any where (powershell.file.script_block_text:\"*DumpCreds*\" and powershell.file.script_block_text:\"*DumpCerts*\") or powershell.file.script_block_text:\"*sekurlsa::logonpasswords*\"",
  "mitre_tactics": ["credential_access"],
  "tags": ["windows", "powershell", "mimikatz", "credential", "eql"],
  "file_path": "/path/to/rules/windows__powershell__powershell_script__posh_ps_potential_invoke_mimikatz.eql"
}
```

---

### 3. execute_detection_rule()

Execute a specific detection rule against Elasticsearch.

**Parameters:**
- `rule_id`: The unique rule identifier
- `index`: Index pattern to search (e.g., "winlogbeat-*", "auditbeat-*")
- `timeframe_minutes` (optional, default: 15): Time window in minutes (0 for no time filter)
- `size` (default: 100, max: 1000): Maximum number of results

**Example:**
```
execute_detection_rule(
    rule_id="windows_powershell_posh_ps_potential_invoke_mimikatz_eql",
    index="winlogbeat-*",
    timeframe_minutes=60
)
```

**Response:**
```json
{
  "rule_info": {
    "rule_id": "windows_powershell_posh_ps_potential_invoke_mimikatz_eql",
    "name": "Posh Ps Potential Invoke Mimikatz",
    "platform": "windows",
    "log_source": "powershell",
    "type": "eql",
    "mitre_tactics": ["credential_access"]
  },
  "total_hits": 5,
  "events": [
    {
      "_index": "winlogbeat-2024.01.15",
      "_source": {
        "@timestamp": "2024-01-15T10:30:45.123Z",
        "event.code": "4104",
        "powershell.file.script_block_text": "Invoke-Mimikatz -DumpCreds",
        "host.name": "DESKTOP-ABC123",
        "user.name": "attacker"
      }
    }
  ],
  "execution_time_ms": 45
}
```

---

### 4. execute_multiple_rules()

Execute multiple detection rules in batch for comprehensive threat hunting.

**Parameters:**
- `rule_ids`: List of rule IDs to execute (max: 50)
- `index`: Index pattern to search
- `timeframe_minutes` (optional, default: 15): Time window in minutes
- `max_results_per_rule` (default: 50, max: 200): Maximum results per rule

**Example:**
```
execute_multiple_rules(
    rule_ids=[
        "windows_powershell_posh_ps_potential_invoke_mimikatz_eql",
        "windows_process_creation_proc_creation_win_reg_screensaver_lucene"
    ],
    index="winlogbeat-*",
    timeframe_minutes=60
)
```

**Response:**
```json
{
  "total_rules_executed": 2,
  "total_hits": 12,
  "rules_with_findings": 2,
  "failed_rules": 0,
  "results_by_rule": {
    "windows_powershell_posh_ps_potential_invoke_mimikatz_eql": {
      "rule_name": "Posh Ps Potential Invoke Mimikatz",
      "hits": 5,
      "events": [...],
      "mitre_tactics": ["credential_access"]
    },
    "windows_process_creation_proc_creation_win_reg_screensaver_lucene": {
      "rule_name": "Proc Creation Win Reg Screensaver",
      "hits": 7,
      "events": [...],
      "mitre_tactics": ["persistence"]
    }
  }
}
```

---

### 5. search_rules_by_mitre_attack()

Search detection rules by MITRE ATT&CK tactic.

**Parameters:**
- `tactic`: MITRE ATT&CK tactic name
  - execution
  - persistence
  - privilege_escalation
  - defense_evasion
  - credential_access
  - discovery
  - lateral_movement
  - collection
  - command_and_control
  - exfiltration
  - impact
- `platform` (optional): Platform filter (windows, linux, macos)
- `limit` (default: 50): Maximum number of results

**Example:**
```
search_rules_by_mitre_attack(
    tactic="credential_access",
    platform="windows"
)
```

**Response:**
```json
{
  "tactic": "credential_access",
  "platform_filter": "windows",
  "total_found": 45,
  "rules": [
    {
      "rule_id": "windows_powershell_posh_ps_potential_invoke_mimikatz_eql",
      "name": "Posh Ps Potential Invoke Mimikatz",
      "platform": "windows",
      "log_source": "powershell",
      "type": "eql",
      "mitre_tactics": ["credential_access"]
    },
    ...
  ]
}
```

---

### 6. hunt_with_rule_category()

Execute all rules in a specific category for comprehensive threat detection.

**Parameters:**
- `platform`: Target platform (windows, linux, macos)
- `category`: Rule category or log source (powershell, process_creation, audit, etc.)
- `index`: Index pattern to search
- `timeframe_minutes` (default: 15): Time window in minutes
- `max_rules` (default: 10, max: 25): Maximum number of rules to execute

**Example:**
```
hunt_with_rule_category(
    platform="windows",
    category="powershell",
    index="winlogbeat-*",
    timeframe_minutes=60
)
```

**Response:**
```json
{
  "total_rules_executed": 10,
  "total_hits": 87,
  "rules_with_findings": 6,
  "failed_rules": 0,
  "results_by_rule": {
    ...
  }
}
```

---

### 7. get_rule_statistics()

Get comprehensive statistics about the detection rule library.

**Example:**
```
get_rule_statistics()
```

**Response:**
```json
{
  "total_rules": 5048,
  "by_platform": {
    "windows": 3200,
    "linux": 850,
    "macos": 180,
    "application": 450,
    "cloud": 280,
    "network": 88
  },
  "by_type": {
    "lucene": 1967,
    "eql": 3081
  },
  "by_log_source": {
    "powershell": 450,
    "process_creation": 1200,
    "builtin": 650,
    "audit": 320,
    ...
  },
  "platforms": ["windows", "linux", "macos", "application", "cloud", "network"],
  "log_sources": ["powershell", "process_creation", "builtin", ...]
}
```

---

## Usage Workflows

### Workflow 1: Investigate Specific Attack Type

**Scenario:** Hunt for credential access attempts on Windows systems

```
# Step 1: Find relevant rules
search_rules_by_mitre_attack(
    tactic="credential_access",
    platform="windows"
)

# Step 2: Get details on interesting rules
get_rule_details("windows_powershell_posh_ps_potential_invoke_mimikatz_eql")

# Step 3: Execute the rule
execute_detection_rule(
    rule_id="windows_powershell_posh_ps_potential_invoke_mimikatz_eql",
    index="winlogbeat-*",
    timeframe_minutes=1440  # Last 24 hours
)

# Step 4: If hits found, analyze with IoC tools
analyze_search_results(results)
```

---

### Workflow 2: Comprehensive Category Hunting

**Scenario:** Thoroughly check all PowerShell activity

```
# Execute all PowerShell rules
hunt_with_rule_category(
    platform="windows",
    category="powershell",
    index="winlogbeat-*",
    timeframe_minutes=60,
    max_rules=25
)

# Results show which rules matched and the events
# Follow up on rules with findings
```

---

### Workflow 3: Browse and Explore Rules

**Scenario:** Explore what detection rules are available

```
# Get overall statistics
get_rule_statistics()

# List Windows rules
list_detection_rules(platform="windows", limit=100)

# Search for specific techniques
list_detection_rules(search_term="lateral movement")

# Find all Linux process creation rules
list_detection_rules(
    platform="linux",
    log_source="process_creation"
)
```

---

### Workflow 4: Targeted Rule Execution

**Scenario:** Execute specific rules based on intelligence

```
# You received threat intel about mimikatz and psexec usage
# Find relevant rules
mimikatz_rules = list_detection_rules(search_term="mimikatz")
psexec_rules = list_detection_rules(search_term="psexec")

# Execute both sets of rules
execute_multiple_rules(
    rule_ids=[
        "windows_powershell_posh_ps_potential_invoke_mimikatz_eql",
        "windows_process_creation_proc_creation_win_psexec_lucene",
        ...
    ],
    index="winlogbeat-*",
    timeframe_minutes=120
)
```

---

## Integration with Existing Tools

The rule system **complements** the existing threat hunting tools:

### Existing Tools (Hardcoded Patterns)
- **hunt_by_timeframe()** - Quick hunting with 8 pre-built attack patterns
- **analyze_failed_logins()** - Fast brute force detection
- **analyze_process_creation()** - Quick suspicious process analysis
- **hunt_for_ioc()** - IoC tracking

**Use when:** You want fast, pre-configured threat hunting

### New Rule System (5000+ Rules)
- **list_detection_rules()** - Browse comprehensive rule library
- **execute_detection_rule()** - Run specific community rules
- **hunt_with_rule_category()** - Comprehensive category-based hunting

**Use when:** You want in-depth, comprehensive detection coverage

---

## Rule File Structure

Rules are stored in the `./rules` directory with a structured naming convention:

```
{platform}__{log_source}__{category}__{rule_name}.{type}
```

**Examples:**
- `windows__powershell__powershell_script__posh_ps_potential_invoke_mimikatz.eql`
- `linux__process_creation__proc_creation_lnx_nice_shell_execution.lucene`
- `application__bitbucket__audit__bitbucket_audit_full_data_export_triggered.lucene`

**Platforms:**
- windows
- linux
- macos
- application
- cloud
- network

**Rule Types:**
- `.lucene` - Lucene query syntax
- `.eql` - Event Query Language

---

## MITRE ATT&CK Mapping

Rules are automatically mapped to MITRE ATT&CK tactics based on keywords:

| Tactic | Keywords |
|--------|----------|
| **Execution** | execution, exec, run, launch |
| **Persistence** | persistence, scheduled, service, startup, registry |
| **Privilege Escalation** | escalation, privilege, admin, sudo, runas |
| **Defense Evasion** | evasion, obfuscation, encoding, bypass, disable |
| **Credential Access** | credential, password, mimikatz, dump, hash |
| **Discovery** | discovery, recon, enumerate, whoami, netstat |
| **Lateral Movement** | lateral, remote, psexec, wmi, rdp |
| **Collection** | collection, clipboard, screenshot, keylog |
| **Command and Control** | c2, beacon, callback, tunnel |
| **Exfiltration** | exfil, upload, transfer, compress |
| **Impact** | impact, delete, encrypt, ransom, wipe |

---

## Best Practices

### 1. Start Broad, Then Narrow

```
# First: Get an overview
get_rule_statistics()

# Then: Browse categories
list_detection_rules(platform="windows")

# Finally: Execute specific rules
execute_detection_rule(rule_id="...", index="winlogbeat-*")
```

### 2. Use Appropriate Time Windows

```
# Recent incidents: 15-60 minutes
timeframe_minutes=60

# Daily hunting: 24 hours
timeframe_minutes=1440

# Weekly review: 7 days
timeframe_minutes=10080

# Historical investigation: No time filter
timeframe_minutes=0
```

### 3. Combine with IoC Analysis

```
# Step 1: Execute rule
results = execute_detection_rule(
    rule_id="windows_powershell_posh_ps_potential_invoke_mimikatz_eql",
    index="winlogbeat-*"
)

# Step 2: If hits found, extract IoCs
if results["total_hits"] > 0:
    analyze_search_results(results["events"])
```

### 4. Batch Similar Rules

```
# Instead of running rules one by one:
# Run all credential access rules together
cred_rules = search_rules_by_mitre_attack(tactic="credential_access")
rule_ids = [r["rule_id"] for r in cred_rules["rules"][:10]]

execute_multiple_rules(
    rule_ids=rule_ids,
    index="winlogbeat-*"
)
```

### 5. Platform-Specific Hunting

```
# Windows environment
hunt_with_rule_category(
    platform="windows",
    category="powershell",
    index="winlogbeat-*"
)

# Linux environment
hunt_with_rule_category(
    platform="linux",
    category="process_creation",
    index="auditbeat-*"
)
```

---

## Performance Tips

1. **Limit Results**: Use `limit` and `size` parameters appropriately
2. **Specific Indices**: Use specific index patterns instead of wildcards
3. **Time Filters**: Always use time filters for large datasets
4. **Batch Execution**: Group related rules in execute_multiple_rules()
5. **Monitor Execution Time**: Check `execution_time_ms` in responses

---

## Troubleshooting

### Rule Returns No Results

**Possible causes:**
1. Rule designed for different log source
2. Events don't exist in the time window
3. Index mapping doesn't match rule fields
4. Rule syntax incompatible with your Elasticsearch version

**Solutions:**
- Check rule details: `get_rule_details(rule_id)`
- Verify log source matches your data
- Expand time window
- Try rules from the same platform and log source

### Rule Execution Fails

**Common errors:**
1. **EQL syntax error**: Rule may need Elasticsearch 7.9+
2. **Field not found**: Index doesn't have required fields
3. **Timeout**: Query too complex or dataset too large

**Solutions:**
- Check Elasticsearch version compatibility
- Review index field mappings
- Increase timeout or reduce time window
- Use Lucene rules instead of EQL for older ES versions

---

## Summary

The Detection Rules System provides:

✅ **5,000+ community detection rules**
✅ **Lucene and EQL query support**
✅ **MITRE ATT&CK framework mapping**
✅ **Platform and log source filtering**
✅ **Batch rule execution**
✅ **Comprehensive threat coverage**
✅ **Integration with existing tools**

**Start exploring:**
```
get_rule_statistics()
list_detection_rules(limit=20)
```

**Happy hunting! 🔍🚀**
