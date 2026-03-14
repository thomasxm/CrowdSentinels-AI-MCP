# AI Agent Integration Guide for Elasticsearch MCP Server

## Overview

This document describes how AI agents should interact with the enhanced Elasticsearch MCP Server for threat hunting, incident response, and security log analysis.

## Table of Contents

1. [AI Agent Capabilities](#ai-agent-capabilities)
2. [MCP-Native Workflow Guidance](#mcp-native-workflow-guidance)
3. [Key Decision-Making Principles](#key-decision-making-principles)
4. [Quick Reference: Tool Usage Patterns](#quick-reference-tool-usage-patterns)
5. [User Interaction Templates](#user-interaction-templates)
6. [Common Scenarios & Agent Responses](#common-scenarios--agent-responses)
7. [Best Practices Summary](#best-practices-summary)
8. [Complete Example: Full Investigation Flow](#complete-example-full-investigation-flow)
9. [Integration with Existing Tools](#integration-with-existing-tools)
10. [Security & Compliance](#security--compliance)

---

## AI Agent Capabilities

### What AI Agents Can Do

AI agents using this MCP server can act as **experienced security analysts** by:

1. **Understanding User Intent**: Interpret vague security questions
2. **Asset Discovery**: Automatically identify relevant log sources
3. **Threat Hunting**: Execute targeted searches for attack patterns
4. **IoC Analysis**: Extract and prioritize indicators of compromise
5. **Decision Making**: Recommend next investigative steps
6. **Report Generation**: Create comprehensive incident reports

### Read-Only Guardrails

**Important**: All threat hunting and analysis tools are **read-only**. Agents:
- ✅ CAN read and analyse security logs
- ✅ CAN search for IoCs and attack patterns
- ✅ CAN generate reports and recommendations
- ❌ CANNOT modify or delete logs
- ❌ CANNOT create or delete indices
- ❌ CANNOT change security configurations

---

## MCP-Native Workflow Guidance

### Overview

CrowdSentinel provides **built-in workflow guidance** through MCP primitives (Resources, Prompts, and Tools). This ensures that **any AI agent** connecting to the server knows the correct investigation workflow - no external configuration required.

### The Iron Law

```
NO INVESTIGATION IS COMPLETE WITHOUT ANALYSIS TOOLS
```

If you have collected data but haven't used analysis tools, the investigation is **INCOMPLETE**.

### Accessing Workflow Guidance

#### MCP Resources (Read-Only Documentation)

AI agents can read workflow documentation directly from the server:

| Resource URI | Content |
|--------------|---------|
| `crowdsentinel://investigation-workflow` | Complete investigation workflow documentation |
| `crowdsentinel://tool-recommendations` | Recommended next steps after each tool |

```python
# Example: Read the workflow documentation
workflow_doc = read_resource("crowdsentinel://investigation-workflow")
```

#### MCP Prompt (Investigation Starter)

Use the `start-investigation` prompt to begin an investigation with proper workflow:

```python
# Example: Start a new investigation with guided workflow
response = invoke_prompt("start-investigation", {
    "description": "Investigating suspicious PowerShell execution on DESKTOP-001"
})
```

#### Workflow Guidance Tools

| Tool | Purpose |
|------|---------|
| `get_investigation_workflow()` | Returns complete workflow documentation and tool recommendations |
| `get_next_step(tool_name)` | Returns recommended next action after using a specific tool |

```python
# Get the complete workflow at start of investigation
workflow = get_investigation_workflow()

# After using a tool, get recommended next step
next_action = get_next_step("smart_search")
# Returns: {"next_step": "analyze_search_results", "hint": "Use analyze_search_results()..."}
```

### Workflow Hints in Tool Outputs

Every search/hunting tool now includes a `workflow_hint` field in its response:

```python
# Example: smart_search response
{
    "total_hits": 150,
    "hits": [...],
    "workflow_hint": {
        "next_step": "analyze_search_results",
        "instruction": "MANDATORY: Use analyze_search_results() on these results...",
        "after_analysis": "Use analyze_kill_chain_stage() to position attack in kill chain"
    }
}
```

**Always follow the `workflow_hint`** - it guides you to the next required step.

### Mandatory Investigation Phases

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    CrowdSentinel Investigation Workflow                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Phase 1: Data Collection                                               │
│  └── threat_hunt_search, smart_search, execute_detection_rule, etc.    │
│                          │                                              │
│                          ▼                                              │
│  Phase 2: Analysis (MANDATORY - DO NOT SKIP!)                          │
│  ├── analyze_search_results() → Extract IoCs, map MITRE ATT&CK         │
│  └── analyze_kill_chain_stage() → Position in Cyber Kill Chain         │
│                          │                                              │
│                          ▼                                              │
│  Phase 3: State Management (For Multi-Query Investigations)            │
│  ├── create_investigation() → Start tracking                           │
│  ├── add_iocs_to_investigation() → Store discovered IoCs               │
│  └── get_shared_iocs() → Cross-correlate                               │
│                          │                                              │
│                          ▼                                              │
│  Phase 4: Reporting (Before Concluding)                                │
│  └── generate_investigation_report() → Comprehensive final report      │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Anti-Pattern Warning

```
❌ WRONG: Run queries → manually summarise → present to user
✅ RIGHT: Run queries → analyze_search_results → analyze_kill_chain_stage
          → generate_investigation_report → present to user
```

---

## Key Decision-Making Principles

### 1. Always Clarify Before Acting
```
User: "Check for attacks"
Agent: Ask -> "Windows or Linux?" "Specific host?" "Timeframe?"
```

### 2. Prioritize by Pyramid of Pain
```
Priority 6 (TTPs) > Priority 5 (Tools) > Priority 4 (Network) > ... > Priority 1 (Hashes)
```

### 3. Always Analyse Results
```
Raw Query Results → analyze_search_results() → Intelligent Insights → User
```

### 4. Map to MITRE ATT&CK
```
Every finding should be explained with MITRE ATT&CK context
```

### 5. Recommend Specific Next Steps
```
Never: "You should investigate"
Always: "I recommend tracking user 'admin' across all systems. Shall I run that query?"
```

---

## Quick Reference: Tool Usage Patterns

### Initial Investigation
```python
# Step 1: Discover assets
assets = discover_all_assets()
indices = get_indices_by_type("windows")  # or "linux"

# Step 2: Hunt for threats
results = hunt_by_timeframe(
    index=indices[0],
    attack_types=["brute_force", "suspicious_process", "lateral_movement"],
    start_time="now-15m"
)

# Step 3: Analyse (ALWAYS!)
analysis = analyze_search_results(results, context="Initial security sweep")

# Step 4: Present findings with recommendations
# (See analysis structure in THREAT_HUNTING_GUIDE.md)
```

### Follow-Up Investigation
```python
# If high-priority IoC found (pyramid_priority >= 5)
for ioc in analysis['iocs_found']:
    if ioc['pyramid_priority'] >= 5:
        followup = hunt_for_ioc(
            index=indices[0],
            ioc=ioc['value'],
            ioc_type=ioc['type'],
            timeframe_minutes=1440  # 24 hours
        )
        analysis2 = analyze_search_results(followup, f"Tracking {ioc['value']}")
```

### Forensic Timeline
```python
# For host investigation
timeline = get_host_activity_timeline(
    index=indices[0],
    hostname="compromised-host",
    start_time="now-48h"
)
```

### Final Report
```python
# Aggregate all analyses
report = generate_investigation_report(
    analysis_results=[analysis1, analysis2, analysis3],
    investigation_context="Complete investigation summary"
)
```

---

## User Interaction Templates

### Template 1: Initial Response
```
"I'll investigate [user's request]. A few questions to ensure accurate analysis:

1. Are you investigating Windows or Linux systems?
2. Specific host or all systems?
3. Timeframe to investigate?

I'll search for [list of attack patterns based on keywords] and provide
detailed findings with MITRE ATT&CK mapping and recommendations."
```

### Template 2: Presenting Findings
```
"Investigation Results:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SEVERITY: [CRITICAL/HIGH/MEDIUM/LOW]

📊 Summary:
- [X] total security events found
- Timeframe: [start] to [end]
- [Y] hosts affected
- [Z] users involved

🔴 CRITICAL (TTPs - Priority 6):
- [Command line patterns, behaviours]
  MITRE: [Technique ID and name]
  Impact: [Why this matters]

🟠 HIGH (Tools - Priority 5):
- [Specific tools/processes]
  MITRE: [Technique ID and name]

🟡 MEDIUM (Network Artifacts - Priority 4):
- [Users, hostnames]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

🎯 Recommended Actions:

A) [Specific investigation #1]
   Why: [Clear rationale]

B) [Specific investigation #2]
   Why: [Clear rationale]

C) [Specific investigation #3]
   Why: [Clear rationale]

Which would you like me to pursue?"
```

### Template 3: Technical Explanation
```
"Detected [event count] [event type] events.

Plain English: [What this means]

Technical Details:
- Event ID: [ID] ([Event name])
- MITRE ATT&CK: [Technique ID] - [Technique name]
- Tactic: [Tactic name]
- Severity: [Why this severity level]

This indicates: [Attack hypothesis]"
```

---

## Common Scenarios & Agent Responses

### Scenario 1: "Check for attacks in last 15 minutes"

**Agent Response**:
```
1. Ask: "Windows or Linux systems?"
2. Discover: get_indices_by_type(answer)
3. Hunt: hunt_by_timeframe(attack_types=[common_patterns], "now-15m")
4. Analyse: analyze_search_results()
5. Present: Formatted findings with MITRE mapping
6. Recommend: 2-3 specific next steps
```

### Scenario 2: "What processes on agent-001?"

**Agent Response**:
```
1. Timeline: get_host_activity_timeline(hostname="agent-001", "now-1h")
2. Processes: analyze_process_creation(timeframe_minutes=60)
3. Filter: For agent-001 specifically
4. Analyse: Check for suspicious processes
5. Present: Chronological list with suspicion flags
6. Alert: If encoded commands or LOLBins found
```

### Scenario 3: "Investigate user 'admin'"

**Agent Response**:
```
1. Hunt: hunt_for_ioc(ioc="admin", ioc_type="user", timeframe_minutes=1440)
2. Analyse: Extract all related IoCs
3. Timeline: Build narrative of admin activity
4. Check: Failed logins, privilege escalation, lateral movement
5. Present: Complete user activity summary
6. Recommend: Containment if compromised
```

---

## Best Practices Summary

### DO:
✅ Always discover assets first (`discover_all_assets()`)
✅ Always analyse results before presenting (`analyze_search_results()`)
✅ Always prioritize by Pyramid of Pain
✅ Always map to MITRE ATT&CK
✅ Always provide specific recommendations
✅ Always explain in plain English
✅ Always generate final reports

### DON'T:
❌ Never present raw search results
❌ Never skip analysis step
❌ Never make write operations
❌ Never assume user intent - ask questions
❌ Never present technical jargon without explanation
❌ Never forget to prioritize IoCs

---

## Complete Example: Full Investigation Flow

```python
"""
Example: User asks "Check for suspicious attacks in last 15 minutes"
"""

# 1. CLARIFY
# Agent asks: "Windows or Linux?" → User: "Windows"

# 2. DISCOVER ASSETS
assets = discover_all_assets()
indices = get_indices_by_type("windows")  # Returns: ["winlogbeat-*"]

# 3. INITIAL HUNT
hunt_results = hunt_by_timeframe(
    index="winlogbeat-*",
    attack_types=["brute_force", "privilege_escalation", "suspicious_process"],
    start_time="now-15m"
)

# 4. ANALYSE
analysis1 = analyze_search_results(
    search_results=hunt_results,
    context="15-minute security sweep"
)

# 5. PRESENT TO USER
print(f"""
Investigation Results:
SEVERITY: {analysis1['severity_assessment'].upper()}

Found {analysis1['summary']['total_events']} security events

CRITICAL IoCs (Pyramid Priority 6):
{[ioc for ioc in analysis1['iocs_found'] if ioc['pyramid_priority'] == 6]}

MITRE ATT&CK Techniques:
{analysis1['mitre_attack_techniques']}

Recommendations:
{analysis1['recommended_followup'][:3]}

Which shall I investigate?
""")

# 6. USER CHOOSES FOLLOW-UP
# User: "A - investigate the suspicious user"

suspicious_user = analysis1['iocs_found'][0]['value']  # Assume first is user

# 7. FOLLOW-UP HUNT
user_activity = hunt_for_ioc(
    index="winlogbeat-*",
    ioc=suspicious_user,
    ioc_type="user",
    timeframe_minutes=1440  # 24 hours
)

# 8. ANALYSE FOLLOW-UP
analysis2 = analyze_search_results(
    search_results=user_activity,
    context=f"Tracking user {suspicious_user}"
)

# 9. GENERATE FINAL REPORT
final_report = generate_investigation_report(
    analysis_results=[analysis1, analysis2],
    investigation_context="Suspected brute force attack investigation"
)

# 10. PRESENT FINAL REPORT
print(f"""
FINAL INVESTIGATION REPORT
Report ID: {final_report['report_id']}

Executive Summary:
{final_report['executive_summary']}

Affected Systems: {final_report['affected_hosts']}
Affected Users: {final_report['affected_users']}

All IoCs: {len(final_report['all_iocs'])}
MITRE Techniques: {len(final_report['all_techniques'])}

Verdict: [Based on findings]
Recommendations: [Containment and remediation steps]
""")
```

---

## Integration with Existing Tools

All 18 new threat hunting tools integrate seamlessly with existing MCP tools:

### Existing Tools (Read-Only):
- `list_indices()` - Compatible with asset discovery
- `search_documents()` - Can be enhanced with analysis
- `get_cluster_health()` - Use for compliance checks
- `get_cluster_stats()` - Use for capacity planning

### New Threat Hunting Tools:
- **Asset Discovery** (4 tools)
- **EQL Queries** (3 tools)
- **Threat Hunting** (6 tools)
- **IoC Analysis** (2 tools)

### Tool Chaining Example:
```python
# Use existing + new tools together
indices = list_indices()  # Existing
metadata = get_index_metadata(indices[0]['index'])  # New
results = search_documents(index=indices[0]['index'], body=query)  # Existing
analysis = analyze_search_results(results, "Investigation")  # New
```

---

## Security & Compliance

### Read-Only Guarantee
All new tools are **read-only** by design:
- No index creation/deletion
- No document modification
- No configuration changes
- No log tampering

### Audit Trail
All queries are logged:
- Timestamp
- Query type
- User context
- Results returned

### Compliance Support
Tools support compliance checks for:
- PCI-DSS logging requirements
- SOC 2 security monitoring
- HIPAA audit trail verification
- General security best practices

---

## Summary

AI agents should:
1. **Ask clarifying questions** before acting
2. **Discover assets** to find correct log sources
3. **Hunt using pre-built patterns** for common attacks
4. **Analyse all results** with intelligent IoC extraction
5. **Prioritize by Pyramid of Pain** (TTPs first!)
6. **Map to MITRE ATT&CK** for context
7. **Explain in plain English** with technical details
8. **Recommend specific actions** not vague suggestions
9. **Generate comprehensive reports** at investigation end

For detailed tool documentation, see [THREAT_HUNTING_GUIDE.md](./THREAT_HUNTING_GUIDE.md).
For architecture details, see [ARCHITECTURE.md](./ARCHITECTURE.md).
