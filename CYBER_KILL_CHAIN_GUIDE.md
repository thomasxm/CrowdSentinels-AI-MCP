# Cyber Kill Chain Integration Guide

## Overview

The Cyber Kill Chain integration maps attacks to the **Lockheed Martin Cyber Kill Chain** framework, helping you understand where in the attack lifecycle adversaries currently are, and enabling you to hunt for evidence of previous stages (to find initial access) or next stages (to prevent progression).

### The Lockheed Martin Cyber Kill Chain

The kill chain represents the stages of a cyberattack from initial reconnaissance to achieving objectives:

```
Reconnaissance → Weaponization → Delivery → Exploitation →
Installation → Command & Control → Actions on Objectives
```

### Key Capabilities

1. **Stage Identification** - Determine which kill chain stage(s) an attack is in based on IoCs
2. **Attack Progression Tracking** - Map events to stages and visualize attack timeline
3. **Adjacent Stage Hunting** - Hunt backwards (how did they get here?) and forwards (what's next?)
4. **50+ Stage-Specific Hunting Queries** - Pre-built queries for each stage
5. **MITRE ATT&CK to Kill Chain Mapping** - Correlate tactics to kill chain stages

---

## The 7 Kill Chain Stages

### Stage 1: Reconnaissance

**What it is:** Adversary gathers information about the target through various means.

**Indicators:**
- Port scanning activity
- DNS enumeration
- WHOIS lookups
- Social media profiling
- Employee enumeration
- Network mapping
- Vulnerability scanning
- Web application probing

**Typical IoCs:**
- Multiple failed connection attempts
- Unusual DNS queries
- Port scan signatures
- Web crawler activity
- Unusual external IPs scanning your network

**Log Sources:**
- Firewall logs
- IDS/IPS logs
- DNS logs
- Web server logs
- Network flow data
- Proxy logs

**Hunting Queries Available:** 4
- Port scans
- DNS enumeration
- Web scanning
- Failed connections

**MITRE ATT&CK Tactics:** Reconnaissance

---

### Stage 2: Weaponization

**What it is:** Adversary creates malicious payload (malware, exploit, document with macro).

**Indicators:**
- Malware creation
- Exploit development
- Malicious document creation
- Payload encoding/obfuscation
- C2 infrastructure setup
- Exploit kit usage

**Note:** Weaponization typically occurs on attacker infrastructure and is **not visible in victim logs**. Evidence is usually found through threat intelligence feeds and sandbox analysis.

**MITRE ATT&CK Tactics:** Resource Development

---

### Stage 3: Delivery

**What it is:** Adversary delivers the weaponized payload to the target.

**Indicators:**
- Phishing emails
- Malicious attachments
- Drive-by downloads
- Watering hole attacks
- USB drops
- Malicious links
- Compromised websites

**Typical IoCs:**
- Phishing email sender addresses
- Malicious URLs
- Suspicious file attachments
- Compromised legitimate sites
- Exploit kit domains
- Malicious advertising (malvertising)

**Log Sources:**
- Email gateway logs
- Web proxy logs
- DNS logs
- Endpoint detection logs
- Network traffic logs
- URL filtering logs

**Hunting Queries Available:** 4
- Phishing emails
- Suspicious downloads
- Malicious URLs
- Web exploits

**MITRE ATT&CK Tactics:** Initial Access

---

### Stage 4: Exploitation

**What it is:** Adversary exploits vulnerability to execute code on target system.

**Indicators:**
- Exploit execution
- Vulnerability exploitation
- Code execution
- Memory corruption
- Privilege escalation attempts
- Browser exploits
- Application crashes

**Typical IoCs:**
- CVE exploitation indicators
- Exploit kit signatures
- Abnormal process execution
- Memory injection
- Shellcode execution
- Application crashes before payload

**Log Sources:**
- Sysmon
- Windows Security logs
- EDR logs
- Application logs
- IDS/IPS logs
- Crash dumps

**Event Codes:** 4688, 4624

**Hunting Queries Available:** 4
- Exploit attempts
- Suspicious process execution
- Memory injection
- Shellcode execution

**MITRE ATT&CK Tactics:** Execution, Privilege Escalation

---

### Stage 5: Installation

**What it is:** Adversary installs malware and establishes persistence.

**Indicators:**
- Malware installation
- Persistence mechanisms
- Backdoor installation
- Registry modifications
- Scheduled tasks creation
- Service creation
- Startup folder modifications
- DLL hijacking

**Typical IoCs:**
- File hashes of installed malware
- Registry keys modified
- Scheduled task names
- Service names
- Startup locations
- DLL paths
- User account creation

**Log Sources:**
- Sysmon
- Windows Security logs
- Windows System logs
- EDR logs
- File integrity monitoring

**Event Codes:** 4688, 7045, 4698, 4720, 4732

**Hunting Queries Available:** 7
- Service creation
- Scheduled task creation
- Registry Run keys
- Startup persistence
- New user creation
- DLL hijacking
- Malware installation

**MITRE ATT&CK Tactics:** Persistence, Defense Evasion

---

### Stage 6: Command and Control (C2)

**What it is:** Adversary establishes command channel to control compromised system.

**Indicators:**
- C2 beaconing
- Outbound connections to known C2
- Unusual network traffic patterns
- DNS tunneling
- Encrypted channels
- Non-standard ports
- Periodic callbacks

**Typical IoCs:**
- C2 IP addresses
- C2 domain names
- User agents
- URL patterns
- JA3 fingerprints
- Certificate hashes
- Beacon intervals

**Log Sources:**
- Firewall logs
- Proxy logs
- DNS logs
- Network flow data
- SSL/TLS inspection logs
- EDR network logs

**Hunting Queries Available:** 7
- C2 beaconing
- DNS tunneling
- Suspicious TLS
- Unusual ports
- Long connections
- Rare domains
- Base64 HTTP traffic

**MITRE ATT&CK Tactics:** Command and Control

---

### Stage 7: Actions on Objectives

**What it is:** Adversary achieves their goal (data theft, destruction, encryption, lateral movement).

**Indicators:**
- Data exfiltration
- File encryption (ransomware)
- Data destruction
- Lateral movement
- Credential theft
- System manipulation
- Service disruption

**Typical IoCs:**
- Large data transfers
- File extensions changed (.encrypted)
- Credential dumping tools
- Lateral movement tools
- Mass file deletion
- Database dumps
- Compression tools usage

**Log Sources:**
- Windows Security logs
- Sysmon
- Firewall logs
- DLP logs
- Database logs
- File server logs
- EDR logs

**Event Codes:** 4624, 4648, 4672, 4688

**Hunting Queries Available:** 10
- Data exfiltration
- Lateral movement
- Credential dumping
- Ransomware
- Mass file deletion
- SMB lateral movement
- PsExec usage
- WMI lateral movement
- Large uploads
- Archive before exfiltration

**MITRE ATT&CK Tactics:** Credential Access, Lateral Movement, Collection, Exfiltration, Impact

---

## MCP Tools

### 1. `analyze_kill_chain_stage`

Identify which kill chain stage(s) an attack is in from IoCs.

**Parameters:**
- `iocs` (required): List of IoC dictionaries with 'type' and 'value'
- `include_hunting_suggestions` (optional): Include adjacent stage hunting suggestions (default: True)

**Supported IoC Types:**
- Network: `ip`, `domain`, `url`, `c2_domain`, `user_agent`, `ja3`
- Files: `file_hash`, `file_path`, `attachment`
- System: `registry_key`, `service_name`, `scheduled_task`, `user_account`
- Activity: `port_scan`, `dns_query`, `email`, `cve`, `exploit`
- Advanced: `credential`, `lateral_movement`, `ransomware`, `data_exfil`

**Returns:**
- Identified stages with confidence scores
- Most likely current stage
- Matching IoCs for each stage
- Hunting suggestions for previous/next stages

**Example:**
```python
# You found these IoCs during investigation
iocs = [
    {"type": "file_hash", "value": "abc123def..."},
    {"type": "registry_key", "value": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware"},
    {"type": "service_name", "value": "MaliciousService"}
]

# Analyze which kill chain stage
analysis = analyze_kill_chain_stage(iocs=iocs)

# Result shows:
# Most likely stage: INSTALLATION (66.7% confidence)
# Hunting suggestions:
#   - Previous stage (EXPLOITATION): How did malware execute?
#   - Next stage (C2): Has C2 been established?
```

---

### 2. `get_kill_chain_overview`

Get complete overview of all 7 Cyber Kill Chain stages.

**Parameters:** None

**Returns:**
- Framework description
- All 7 stages with descriptions
- Indicators for each stage
- Typical IoCs for each stage
- Log sources to check
- MITRE ATT&CK tactic mappings
- Number of hunting queries available per stage

**Example:**
```python
# Get overview to understand the framework
overview = get_kill_chain_overview()

# Review specific stage
installation_stage = overview['stages']['INSTALLATION']
print(installation_stage['indicators'])
# Shows: Malware installation, persistence mechanisms, registry mods, etc.
```

---

### 3. `map_events_to_kill_chain`

Map Elasticsearch events to kill chain stages.

**Parameters:**
- `events` (required): List of Elasticsearch event documents

**Returns:**
- Event count per stage
- List of events for each identified stage
- Stage distribution summary
- Attack progression timeline

**Example:**
```python
# Step 1: Run threat hunting query
results = hunt_by_timeframe(
    index="winlogbeat-*",
    timeframe_minutes=60,
    attack_patterns=["all"]
)

# Step 2: Map events to kill chain
mapping = map_events_to_kill_chain(events=results['events'])

# Result shows attack progression:
# Stage 3 (DELIVERY): 5 events
# Stage 4 (EXPLOITATION): 12 events
# Stage 5 (INSTALLATION): 8 events
# Stage 6 (C2): 3 events
# → Attack has progressed through 4 stages!
```

---

### 4. `hunt_by_kill_chain_stage`

Hunt for indicators of a specific kill chain stage.

**Parameters:**
- `index` (required): Index pattern to search
- `stage` (required): Kill chain stage name
- `timeframe_minutes` (optional): Time window (default: 60)
- `host` (optional): Specific hostname
- `size` (optional): Max results per query (default: 100)

**Valid Stages:**
- RECONNAISSANCE
- DELIVERY
- EXPLOITATION
- INSTALLATION
- COMMAND_AND_CONTROL
- ACTIONS_ON_OBJECTIVES

**Returns:**
- Stage information
- Results from all stage-specific queries
- Total hits found
- Assessment and recommendations

**Example:**
```python
# Hunt for Installation stage indicators
hunt_by_kill_chain_stage(
    index="winlogbeat-*",
    stage="INSTALLATION",
    timeframe_minutes=240
)

# Executes 7 hunting queries:
# - Service creation
# - Scheduled task creation
# - Registry Run keys
# - Startup persistence
# - New user creation
# - DLL hijacking
# - Malware installation

# Returns findings from all queries with recommendations
```

---

### 5. `hunt_adjacent_stages`

Hunt for IoCs in stages before/after the current attack stage.

**Parameters:**
- `index` (required): Index pattern to search
- `current_stage` (required): The stage you've identified
- `timeframe_minutes` (optional): Time window (default: 120)
- `hunt_previous` (optional): Hunt for previous stage (default: True)
- `hunt_next` (optional): Hunt for next stage (default: True)
- `host` (optional): Specific hostname

**Returns:**
- Current stage information
- Previous stage hunting results
- Next stage hunting results
- Attack progression analysis
- Recommendations

**Example:**
```python
# You detected C2 beaconing
hunt_adjacent_stages(
    index="winlogbeat-*",
    current_stage="COMMAND_AND_CONTROL",
    timeframe_minutes=240
)

# Hunts backwards for INSTALLATION:
#   - How did malware persist?
#   - Finds: Service created, registry key modified
#
# Hunts forwards for ACTIONS_ON_OBJECTIVES:
#   - What are they doing now?
#   - Finds: Lateral movement attempts, credential dumping

# Provides recommendations:
# ✓ Previous stage (Installation) shows activity - initial persistence identified
# 🚨 CRITICAL: Next stage (Actions on Objectives) shows activity - attack progressing!
#    Immediate action required to prevent further damage
```

---

## Complete Investigation Workflows

### Workflow 1: Initial Compromise Investigation

**Scenario:** Alert fired for suspicious PowerShell execution

```python
# Step 1: Identify current stage from the alert
iocs = [
    {"type": "exploit", "value": "PowerShell Invoke-Expression"},
    {"type": "process", "value": "powershell.exe -encodedcommand"}
]

stage_analysis = analyze_kill_chain_stage(iocs=iocs)
# Result: Most likely stage = EXPLOITATION

# Step 2: Hunt for adjacent stages
adjacent_hunt = hunt_adjacent_stages(
    index="winlogbeat-*",
    current_stage="EXPLOITATION",
    timeframe_minutes=360,
    hunt_previous=True,  # Find delivery method
    hunt_next=True       # Check if they installed persistence
)

# Step 3: Analyze results
if adjacent_hunt["previous_stage_hunt"]["total_hits"] > 0:
    print("Delivery mechanism identified")
    # Review phishing email / malicious download

if adjacent_hunt["next_stage_hunt"]["total_hits"] > 0:
    print("⚠ Malware was installed!")
    # Hunt for C2 next

# Step 4: Map all events to see full attack timeline
all_events = hunt_by_timeframe(
    index="winlogbeat-*",
    attack_types=["all"],
    start_time="now-6h"
)

timeline = map_events_to_kill_chain(events=all_events["events"])
# Shows complete attack progression
```

---

### Workflow 2: C2 Beaconing Detected

**Scenario:** Network monitoring detected C2 beaconing

```python
# Step 1: Confirm C2 stage
hunt_by_kill_chain_stage(
    index="packetbeat-*",
    stage="COMMAND_AND_CONTROL",
    timeframe_minutes=1440,  # 24 hours
    host="compromised-workstation"
)

# Step 2: Hunt backwards to find installation
hunt_backwards = hunt_adjacent_stages(
    index="winlogbeat-*",
    current_stage="COMMAND_AND_CONTROL",
    timeframe_minutes=2880,  # 48 hours
    hunt_previous=True,
    hunt_next=False,  # Don't care about next yet
    host="compromised-workstation"
)

# Result: Found installation stage
# - Service created: "WindowsUpdate" (malicious)
# - Registry Run key: malware.exe
# - Scheduled task: hourly execution

# Step 3: Now hunt forwards for Actions on Objectives
hunt_forwards = hunt_by_kill_chain_stage(
    index="winlogbeat-*",
    stage="ACTIONS_ON_OBJECTIVES",
    timeframe_minutes=720,
    host="compromised-workstation"
)

# If hits found: Immediate incident response needed!
# If no hits: Opportunity to prevent - implement controls now
```

---

### Workflow 3: Ransomware Response

**Scenario:** Files are being encrypted

```python
# Step 1: This is Actions on Objectives stage
iocs = [
    {"type": "ransomware", "value": "file.encrypted"},
    {"type": "file_path", "value": "C:\\Users\\*\\*.encrypted"}
]

stage = analyze_kill_chain_stage(iocs=iocs)
# Result: ACTIONS_ON_OBJECTIVES

# Step 2: Hunt backwards through ALL previous stages
stages_to_hunt = [
    "COMMAND_AND_CONTROL",
    "INSTALLATION",
    "EXPLOITATION",
    "DELIVERY",
    "RECONNAISSANCE"
]

timeline = {}
for stage_name in stages_to_hunt:
    results = hunt_by_kill_chain_stage(
        index="winlogbeat-*",
        stage=stage_name,
        timeframe_minutes=10080,  # 7 days
        host="ransomware-victim"
    )
    timeline[stage_name] = results

# Reconstruction shows:
# - Reconnaissance: Port scan 7 days ago
# - Delivery: Phishing email 5 days ago
# - Exploitation: Malicious macro executed
# - Installation: Ransomware installed 3 days ago
# - C2: Beaconing to attacker
# - Actions: Encryption started today

# Now you have the complete attack timeline for forensics/legal
```

---

### Workflow 4: Proactive Threat Hunting

**Scenario:** Proactively hunting for undetected compromises

```python
# Step 1: Hunt through all stages systematically
all_stages = [
    "RECONNAISSANCE",
    "DELIVERY",
    "EXPLOITATION",
    "INSTALLATION",
    "COMMAND_AND_CONTROL",
    "ACTIONS_ON_OBJECTIVES"
]

findings = {}

for stage in all_stages:
    print(f"Hunting for {stage}...")

    results = hunt_by_kill_chain_stage(
        index="*beat-*",  # All indices
        stage=stage,
        timeframe_minutes=1440  # 24 hours
    )

    if results["total_hits"] > 0:
        findings[stage] = results
        print(f"  ⚠ Found {results['total_hits']} hits!")

# Step 2: Investigate any findings
for stage, result in findings.items():
    print(f"\nInvestigating {stage}:")

    # Extract hosts with activity
    hosts = set()
    for query_result in result["hunting_results"].values():
        for event in query_result.get("events", []):
            host = event.get("_source", {}).get("host", {}).get("name")
            if host:
                hosts.add(host)

    # Hunt adjacent stages for each affected host
    for host in hosts:
        adjacent = hunt_adjacent_stages(
            index="*beat-*",
            current_stage=stage,
            timeframe_minutes=2880,
            host=host
        )

        # Determine if this is a complete compromise
        if adjacent["attack_progression_analysis"]["progression_complete"]:
            print(f"  🚨 COMPLETE COMPROMISE on {host}")
```

---

## Integration with Other Tools

### With Investigation Prompts

```python
# Step 1: Quick triage with investigation prompts
triage = quick_triage(
    platform="windows",
    index="winlogbeat-*",
    host="suspicious-host",
    timeframe_minutes=120
)

# Step 2: Extract IoCs from triage results
iocs = []
for finding in triage["findings"]:
    for event in finding["top_events"]:
        # Extract IPs, hashes, etc.
        source = event.get("_source", {})
        if "source" in source and "ip" in source["source"]:
            iocs.append({"type": "ip", "value": source["source"]["ip"]})

# Step 3: Map IoCs to kill chain
kill_chain_analysis = analyze_kill_chain_stage(iocs=iocs)

# Step 4: Hunt adjacent stages
if kill_chain_analysis["most_likely_stage"]:
    hunt_adjacent_stages(
        index="winlogbeat-*",
        current_stage=kill_chain_analysis["most_likely_stage"],
        timeframe_minutes=240,
        host="suspicious-host"
    )
```

---

### With Detection Rules

```python
# Step 1: Execute detection rules
rule_results = execute_multiple_rules(
    rule_ids=["mimikatz_detection", "lateral_movement_psexec"],
    index="winlogbeat-*",
    timeframe_minutes=60
)

# Step 2: Map detections to kill chain
detection_events = []
for rule_result in rule_results["results"]:
    if rule_result["total_matches"] > 0:
        detection_events.extend(rule_result["matches"])

kill_chain_mapping = map_events_to_kill_chain(events=detection_events)

# Result shows which stages have detections
# Example: Credential Access (Stage 7) detected
#          → Hunt backwards for Installation, C2

# Step 3: Hunt for earlier stages
for stage_name in kill_chain_mapping["attack_progression"]:
    stage_num = kill_chain_mapping["stage_distribution"][stage_name]["stage_number"]

    # Hunt previous stage
    if stage_num > 1:
        previous_stage_num = stage_num - 1
        # Find stage name by number and hunt
```

---

## Best Practices

### 1. Start with Stage Identification

Always identify the current stage before hunting:

```python
# Extract IoCs from your investigation
iocs = [...]

# Identify stage
analysis = analyze_kill_chain_stage(iocs=iocs)

# Use the identified stage for targeted hunting
current_stage = analysis["most_likely_stage"]
```

### 2. Hunt Both Directions

When you find a stage, hunt both backwards and forwards:

- **Backwards**: Find initial access vector (root cause)
- **Forwards**: Predict and prevent next moves

```python
hunt_adjacent_stages(
    index="winlogbeat-*",
    current_stage="INSTALLATION",
    hunt_previous=True,  # How did they get here?
    hunt_next=True       # What's next?
)
```

### 3. Adjust Timeframes Based on Stage

Different stages require different time windows:

- **Reconnaissance**: Hours to days before attack
- **Delivery**: Hours before exploitation
- **Exploitation**: Minutes to hours
- **Installation**: Immediate after exploitation
- **C2**: Ongoing during compromise
- **Actions on Objectives**: After C2 established

```python
# For Installation (recent)
hunt_by_kill_chain_stage(stage="INSTALLATION", timeframe_minutes=60)

# For Reconnaissance (days ago)
hunt_by_kill_chain_stage(stage="RECONNAISSANCE", timeframe_minutes=10080)  # 7 days
```

### 4. Use Stage-Specific Log Sources

Each stage has optimal log sources:

- **Reconnaissance**: Firewall, IDS, DNS
- **Delivery**: Email gateway, proxy, DNS
- **Exploitation**: Sysmon, EDR, security logs
- **Installation**: Sysmon, security logs, file integrity
- **C2**: Firewall, proxy, DNS, network flow
- **Actions on Objectives**: All of the above + DLP

### 5. Map Complete Attack Timeline

For incident response, map the entire attack:

```python
# Get all events from investigation period
all_events = hunt_by_timeframe(...)

# Map to kill chain
timeline = map_events_to_kill_chain(events=all_events["events"])

# Review attack_progression to see the full story
progression = timeline["attack_progression"]
# Shows: Stage 1 → Stage 3 → Stage 5 → Stage 6 → Stage 7
# (Skipped stages: Weaponization, Delivery - investigate why)
```

---

## Quick Reference

### Kill Chain Stages Summary

| Stage | Number | Focus | Hunt Time |
|-------|--------|-------|-----------|
| Reconnaissance | 1 | Information gathering | Days before |
| Weaponization | 2 | Payload creation | Not visible |
| Delivery | 3 | Payload delivery | Hours before |
| Exploitation | 4 | Code execution | Minutes to hours |
| Installation | 5 | Persistence | Immediate |
| C2 | 6 | Command channel | Ongoing |
| Actions on Objectives | 7 | Goal achievement | After C2 |

### Common IoC to Stage Mappings

| IoC Type | Primary Stage | Secondary Stages |
|----------|---------------|------------------|
| port_scan | Reconnaissance | - |
| email | Delivery | - |
| url, domain | Delivery | C2 |
| cve, exploit | Exploitation | - |
| file_hash | Installation | Weaponization |
| registry_key | Installation | - |
| service_name | Installation | - |
| c2_domain, user_agent | C2 | - |
| lateral_movement | Actions on Objectives | - |
| credential, ransomware | Actions on Objectives | - |

---

**Last Updated:** 2025-12-21
**Version:** 1.0
