# Chainsaw Log Analyzer Integration Guide

## Table of Contents
- [Overview](#overview)
- [What is Chainsaw?](#what-is-chainsaw)
- [Architecture](#architecture)
- [MCP Tools](#mcp-tools)
- [Frameworks](#frameworks)
  - [Pyramid of Pain](#pyramid-of-pain)
  - [Diamond Model](#diamond-model)
- [Usage Examples](#usage-examples)
- [Investigation Workflows](#investigation-workflows)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)
- [Quick Reference](#quick-reference)

---

## Overview

The Chainsaw Log Analyzer integration brings **Windows EVTX hunting capabilities** to the Elasticsearch MCP server. Chainsaw is a fast, Rust-based tool for searching and hunting through Windows Event Logs using Sigma detection rules.

### Key Capabilities

- **Sigma Rule Hunting**: Execute 3,000+ Sigma rules against EVTX files
- **IoC Search**: Search for specific indicators (IPs, domains, process names, etc.)
- **Iterative Hunting**: Multi-stage hunting that follows discovered IoCs
- **Pyramid of Pain**: Categorize IoCs by difficulty for attackers to change
- **Diamond Model**: Map detections to Adversary, Capability, Infrastructure, and Victim
- **Time Filtering**: Filter events by specific time ranges
- **Sample Dataset**: Includes EVTX-ATTACK-SAMPLES for testing

### What's Included

- **6 MCP Tools** for hunting and analysis
- **ChainsawClient** for executing Chainsaw commands
- **Pyramid of Pain** framework integration
- **Diamond Model** of Intrusion Analysis
- **Sigma Rules** (3,000+ rules cloned from SigmaHQ)
- **Sample EVTX Files** (EVTX-ATTACK-SAMPLES)
- **Automatic Setup** via setup.sh script

---

## What is Chainsaw?

[Chainsaw](https://github.com/WithSecureLabs/chainsaw) is a powerful Windows Event Log (EVTX) analysis tool developed by WithSecure Labs (formerly F-Secure). It provides:

### Features

1. **Fast Searching**: Rust-based performance for rapid EVTX analysis
2. **Sigma Rule Support**: Execute Sigma detection rules
3. **Hunt Mode**: Search using Sigma rules to detect threats
4. **Search Mode**: Search for specific terms (IPs, domains, process names)
5. **JSON Output**: Machine-readable output for automation
6. **Time Filtering**: Filter events by timestamp ranges
7. **Event ID Filtering**: Target specific Windows Event IDs

### Why Chainsaw?

- **Speed**: Processes EVTX files 10-100x faster than traditional tools
- **Detection Rules**: Leverages community Sigma rules
- **Forensics**: Essential for Windows incident response
- **Automation**: Perfect for batch processing and scripting
- **Open Source**: Free and actively maintained

---

## Architecture

### Directory Structure

```
./chainsaw/
├── chainsaw                    # Chainsaw binary
├── EVTX-ATTACK-SAMPLES/       # Sample EVTX files for testing
├── mappings/                   # Field mappings for Sigma rules
│   └── sigma-event-logs-all.yml
├── rules/                      # Custom Chainsaw rules
└── sigma/                      # Sigma detection rules (3,000+)
    ├── windows/
    ├── linux/
    ├── cloud/
    └── ...
```

### Components

1. **ChainsawClient** (`src/clients/common/chainsaw_client.py`)
   - Executes Chainsaw commands via subprocess
   - Parses JSON output
   - Implements Pyramid of Pain categorization
   - Implements Diamond Model mapping

2. **ChainsawHuntingTools** (`src/tools/chainsaw_hunting.py`)
   - 6 MCP tools for hunting and analysis
   - Registered with FastMCP server
   - Exception handling wrapper

3. **Setup Script** (`setup.sh`)
   - Downloads and installs Chainsaw
   - Clones Sigma rules
   - Downloads EVTX samples
   - Verifies installation

---

## MCP Tools

### 1. `hunt_with_sigma_rules`

Hunt for threats in EVTX logs using Sigma detection rules.

**Purpose**: Execute Sigma rules against Windows Event Logs to detect known attack patterns.

**Parameters**:
- `evtx_path` (required): Path to EVTX file or directory
- `sigma_rules_path` (optional): Path to Sigma rules directory (default: chainsaw/sigma)
- `mapping_path` (optional): Path to mapping file (default: chainsaw/mappings/sigma-event-logs-all.yml)
- `custom_rules_path` (optional): Path to custom rules directory
- `from_time` (optional): Start timestamp (ISO format: 2019-03-17T19:09:39)
- `to_time` (optional): End timestamp (ISO format)
- `output_format` (optional): Output format (json, csv) - default: json

**Returns**:
```python
{
    "success": True,
    "total_detections": 15,
    "detections": [
        {
            "document": {
                "data": {
                    "EventID": 4688,
                    "Image": "C:\\Windows\\System32\\cmd.exe",
                    "CommandLine": "cmd.exe /c whoami",
                    ...
                }
            },
            "group": "Suspicious Process",
            "name": "Suspicious Command Execution",
            "level": "high",
            "authors": ["..."],
            "references": ["..."]
        },
        ...
    ]
}
```

**Example**:
```python
# Hunt in single EVTX file
hunt_with_sigma_rules(
    evtx_path="./logs/Security.evtx",
    from_time="2024-01-01T00:00:00",
    to_time="2024-01-02T00:00:00"
)

# Hunt in directory of EVTX files
hunt_with_sigma_rules(
    evtx_path="./logs/",
    sigma_rules_path="./custom_sigma_rules/"
)
```

---

### 2. `search_ioc_in_evtx`

Search for a specific IoC (Indicator of Compromise) in EVTX logs.

**Purpose**: Find all events containing a specific IoC (IP, domain, hash, process name, etc.).

**Parameters**:
- `evtx_path` (required): Path to EVTX file or directory
- `ioc` (required): The IoC value to search for (e.g., "192.168.1.100", "evil.com")
- `ioc_type` (required): Type of IoC (ip, domain, hash, process_name, user, file_path, etc.)
- `case_insensitive` (optional): Case-insensitive search - default: True
- `event_id` (optional): Filter by specific Event ID
- `output_format` (optional): Output format (json, csv) - default: json

**Returns**:
```python
{
    "success": True,
    "ioc": "192.168.1.100",
    "ioc_type": "ip",
    "pyramid_of_pain": {
        "level": 2,
        "name": "IP Addresses",
        "difficulty": "Easy",
        "priority": 5
    },
    "total_matches": 23,
    "matches": [
        {
            "EventID": 3,
            "Image": "C:\\Windows\\System32\\svchost.exe",
            "DestinationIp": "192.168.1.100",
            "DestinationPort": 443,
            ...
        },
        ...
    ]
}
```

**Example**:
```python
# Search for suspicious IP
search_ioc_in_evtx(
    evtx_path="./logs/Security.evtx",
    ioc="192.168.1.100",
    ioc_type="ip"
)

# Search for malicious domain
search_ioc_in_evtx(
    evtx_path="./logs/",
    ioc="evil.com",
    ioc_type="domain",
    case_insensitive=True
)

# Search for specific process
search_ioc_in_evtx(
    evtx_path="./logs/System.evtx",
    ioc="mimikatz.exe",
    ioc_type="process_name",
    event_id=4688
)
```

---

### 3. `iterative_hunt`

Perform multi-stage threat hunting starting from an initial IoC.

**Purpose**: Start with one IoC, discover related IoCs, and automatically hunt for them in a cascading investigation.

**Parameters**:
- `evtx_path` (required): Path to EVTX file or directory
- `initial_ioc` (required): Starting IoC value
- `initial_ioc_type` (required): Type of initial IoC
- `max_iterations` (optional): Maximum hunting iterations - default: 3
- `from_time` (optional): Start timestamp
- `to_time` (optional): End timestamp

**Returns**:
```python
{
    "success": True,
    "initial_ioc": "evil.com",
    "initial_ioc_type": "domain",
    "total_iterations": 3,
    "iterations": [
        {
            "iteration": 1,
            "ioc": "evil.com",
            "ioc_type": "domain",
            "matches": 5,
            "discovered_iocs": [
                {"type": "ip", "value": "192.168.1.100"},
                {"type": "process_name", "value": "malware.exe"}
            ]
        },
        {
            "iteration": 2,
            "ioc": "192.168.1.100",
            "ioc_type": "ip",
            "matches": 12,
            "discovered_iocs": [...]
        },
        ...
    ],
    "total_unique_iocs": 15,
    "pyramid_summary": {
        "high_priority": 3,  # TTPs, Tools
        "medium_priority": 5,  # Artifacts
        "low_priority": 7  # Hashes, IPs, Domains
    }
}
```

**Example**:
```python
# Start with suspicious domain, discover related IoCs
iterative_hunt(
    evtx_path="./logs/",
    initial_ioc="evil.com",
    initial_ioc_type="domain",
    max_iterations=3
)

# Start with known malicious IP
iterative_hunt(
    evtx_path="./logs/Security.evtx",
    initial_ioc="192.168.1.100",
    initial_ioc_type="ip",
    max_iterations=5,
    from_time="2024-01-01T00:00:00"
)
```

**How It Works**:
1. **Iteration 1**: Search for initial IoC (e.g., domain "evil.com")
2. **Extract**: Find related IoCs in results (IPs, processes, users)
3. **Iteration 2**: Search for each discovered IoC
4. **Repeat**: Continue until max_iterations or no new IoCs found
5. **Prioritize**: Use Pyramid of Pain to prioritize high-value IoCs
6. **Summary**: Provide complete attack picture

---

### 4. `get_pyramid_of_pain_guide`

Get the Pyramid of Pain framework guide for IoC prioritisation.

**Purpose**: Understand which IoCs are most valuable to detect (hardest for attackers to change).

**Parameters**: None

**Returns**:
```python
{
    "framework": "Pyramid of Pain",
    "description": "Categorizes IoCs by difficulty for attackers to change",
    "levels": [
        {
            "level": 6,
            "name": "TTPs (Tactics, Techniques, Procedures)",
            "difficulty": "Tough",
            "description": "Hardest for attackers to change",
            "priority": 1,
            "examples": ["Credential dumping", "Lateral movement", "Persistence"]
        },
        {
            "level": 5,
            "name": "Tools",
            "difficulty": "Challenging",
            "priority": 2,
            "examples": ["mimikatz", "psexec", "cobalt strike"]
        },
        ...
    ],
    "usage": "Focus detection on higher levels (TTPs, Tools) for lasting impact"
}
```

**Example**:
```python
# Get framework guide
guide = get_pyramid_of_pain_guide()

# Understanding levels:
# Level 6 (TTPs): Best to detect - attackers can't easily change their techniques
# Level 5 (Tools): Good to detect - requires new tools
# Level 4 (Artifacts): Moderate value - registry keys, file paths
# Level 3 (Domains): Easy to change - new domain registration
# Level 2 (IPs): Very easy to change - new infrastructure
# Level 1 (Hashes): Trivial to change - recompile malware
```

---

### 5. `get_diamond_model_guide`

Get the Diamond Model of Intrusion Analysis framework guide.

**Purpose**: Understand how to map attack events to the four vertices of the Diamond Model.

**Parameters**: None

**Returns**:
```python
{
    "framework": "Diamond Model of Intrusion Analysis",
    "description": "Maps attacks to 4 vertices: Adversary, Capability, Infrastructure, Victim",
    "vertices": [
        {
            "vertex": "Adversary",
            "description": "The attacker or threat actor",
            "elements": ["Threat actor identity", "Attribution", "Motivation", "Intent"]
        },
        {
            "vertex": "Capability",
            "description": "Tools and techniques used by adversary",
            "elements": ["Malware", "Exploits", "Tools", "TTPs", "Skills"]
        },
        {
            "vertex": "Infrastructure",
            "description": "Physical/logical resources used in attack",
            "elements": ["IP addresses", "Domains", "Email addresses", "C2 servers"]
        },
        {
            "vertex": "Victim",
            "description": "Target of the attack",
            "elements": ["Target systems", "Affected hosts", "Users", "Assets"]
        }
    ],
    "usage": "Map each detection to one or more vertices to understand attack components"
}
```

**Example**:
```python
# Get framework guide
guide = get_diamond_model_guide()

# Mapping a detection:
# Adversary: APT29 (if known)
# Capability: PowerShell Empire, mimikatz
# Infrastructure: evil.com, 192.168.1.100
# Victim: WORKSTATION-01, user "admin"
```

---

### 6. `analyze_chainsaw_results`

Analyse Chainsaw hunt/search results with Pyramid of Pain and Diamond Model.

**Purpose**: Take raw Chainsaw results and provide intelligence analysis using both frameworks.

**Parameters**:
- `results` (required): Chainsaw hunt or search results (JSON)
- `analysis_type` (optional): Type of analysis (pyramid, diamond, both) - default: both

**Returns**:
```python
{
    "summary": {
        "total_detections": 25,
        "unique_iocs": 18,
        "time_span": "2024-01-01 to 2024-01-05",
        "most_active_host": "WORKSTATION-01"
    },
    "pyramid_analysis": {
        "level_6_ttps": [
            {"ttp": "Credential Dumping", "count": 3},
            {"ttp": "Lateral Movement", "count": 5}
        ],
        "level_5_tools": [
            {"tool": "mimikatz", "count": 3},
            {"tool": "psexec", "count": 2}
        ],
        "level_4_artifacts": [...],
        "level_3_domains": [...],
        "level_2_ips": [...],
        "level_1_hashes": [...],
        "priority_recommendations": [
            "Focus on detecting Credential Dumping TTPs (3 instances)",
            "Monitor for mimikatz tool usage (3 instances)",
            ...
        ]
    },
    "diamond_analysis": {
        "adversary": {
            "identified": False,
            "indicators": []
        },
        "capability": {
            "identified": True,
            "tools": ["mimikatz.exe", "psexec.exe"],
            "techniques": ["LSASS memory dumping", "SMB lateral movement"]
        },
        "infrastructure": {
            "identified": True,
            "ips": ["192.168.1.100"],
            "domains": ["evil.com"]
        },
        "victim": {
            "identified": True,
            "hosts": ["WORKSTATION-01", "WORKSTATION-02"],
            "users": ["admin", "user1"]
        }
    },
    "recommendations": [
        "High priority: Detected credential dumping (Pyramid Level 6)",
        "Medium priority: Block evil.com domain (Pyramid Level 3)",
        "Hunt for lateral movement to other systems (Diamond: Victim expansion)"
    ]
}
```

**Example**:
```python
# Run hunt first
hunt_results = hunt_with_sigma_rules(evtx_path="./logs/Security.evtx")

# Analyze results with both frameworks
analysis = analyze_chainsaw_results(
    results=hunt_results,
    analysis_type="both"
)

# Use Pyramid of Pain only
pyramid_only = analyze_chainsaw_results(
    results=hunt_results,
    analysis_type="pyramid"
)
```

---

## Frameworks

### Pyramid of Pain

The **Pyramid of Pain** categorizes Indicators of Compromise (IoCs) by how difficult they are for attackers to change.

```
       Level 6: TTPs (Tough) ◄─── HIGHEST PRIORITY
      /                          \
     /   Level 5: Tools            \
    /   (Challenging)               \
   /                                 \
  /  Level 4: Network/Host Artifacts  \
 /   (Annoying)                        \
/                                       \
Level 3: Domain Names (Simple)
Level 2: IP Addresses (Easy)
Level 1: Hash Values (Trivial) ◄─── LOWEST PRIORITY
```

#### Levels Explained

**Level 6: TTPs (Tactics, Techniques, Procedures)**
- **Difficulty**: Tough - Hardest for attackers to change
- **Priority**: HIGHEST (Priority 1)
- **Examples**: Credential dumping, lateral movement, persistence mechanisms
- **Why Important**: These represent attacker behaviour patterns that rarely change
- **Detection Value**: Detecting TTPs provides long-term protection

**Level 5: Tools**
- **Difficulty**: Challenging
- **Priority**: HIGH (Priority 2)
- **Examples**: mimikatz, psexec, Cobalt Strike, PowerShell Empire
- **Why Important**: Attackers must develop or acquire new tools
- **Detection Value**: Tool detection forces attackers to change their arsenal

**Level 4: Network/Host Artifacts**
- **Difficulty**: Annoying
- **Priority**: MEDIUM (Priority 3)
- **Examples**: User-Agent strings, registry keys, file paths, service names
- **Why Important**: Requires some effort to modify
- **Detection Value**: Good for specific threat hunting

**Level 3: Domain Names**
- **Difficulty**: Simple
- **Priority**: LOW-MEDIUM (Priority 4)
- **Examples**: evil.com, malicious.net, c2.attacker.com
- **Why Important**: Easy to register new domains
- **Detection Value**: Temporary blocking, short-term protection

**Level 2: IP Addresses**
- **Difficulty**: Easy
- **Priority**: LOW (Priority 5)
- **Examples**: 192.0.2.100, 203.0.113.42
- **Why Important**: Trivial to change infrastructure
- **Detection Value**: Very short-term blocking only

**Level 1: Hash Values**
- **Difficulty**: Trivial
- **Priority**: LOWEST (Priority 6)
- **Examples**: MD5, SHA1, SHA256 file hashes
- **Why Important**: Single byte change creates new hash
- **Detection Value**: Only catches exact same file

#### Using Pyramid of Pain

**When Hunting**:
1. **Prioritize Level 6 and 5**: Focus on TTPs and Tools
2. **Build Detections**: Create rules for high-level indicators
3. **Lower Levels for Context**: Use IPs/domains/hashes to understand scope
4. **Report Up the Pyramid**: Always try to identify TTPs from low-level IoCs

**Example Investigation**:
```
Found hash: abc123... (Level 1)
    ↓
Analysed file → Identified: mimikatz (Level 5)
    ↓
Analysed behaviour → Identified: Credential Dumping (Level 6)
    ↓
CREATE DETECTION FOR LEVEL 6 (Credential Dumping behaviour)
NOT for Level 1 (hash - easily changed)
```

---

### Diamond Model

The **Diamond Model of Intrusion Analysis** maps attack events to four vertices representing core attack components.

```
         Adversary
            / \
           /   \
          /     \
    Capability  Infrastructure
          \     /
           \   /
            \ /
          Victim
```

#### The Four Vertices

**1. Adversary**
- **Definition**: The threat actor or attacker
- **Elements**:
  - Threat actor identity (APT29, FIN7, etc.)
  - Attribution indicators
  - Motivation (financial, espionage, disruption)
  - Intent and goals
- **Example IoCs**: Threat actor TTPs, known tools, campaign patterns

**2. Capability**
- **Definition**: Tools, techniques, and procedures used
- **Elements**:
  - Malware families
  - Exploits used
  - Tools (mimikatz, psexec)
  - TTPs (credential dumping, lateral movement)
  - Technical skills required
- **Example IoCs**: Process names, command lines, malware hashes

**3. Infrastructure**
- **Definition**: Physical and logical resources used in the attack
- **Elements**:
  - IP addresses
  - Domain names
  - Email addresses
  - C2 (Command & Control) servers
  - Network infrastructure
- **Example IoCs**: IPs, domains, URLs, ports

**4. Victim**
- **Definition**: The target of the attack
- **Elements**:
  - Target systems and hosts
  - Affected users
  - Compromised accounts
  - Assets at risk
  - Business impact
- **Example IoCs**: Hostnames, usernames, affected systems

#### Using Diamond Model

**Mapping a Detection**:
```python
Detection: Suspicious PowerShell execution on WORKSTATION-01

Adversary: Unknown (no attribution yet)
    - No TTP match to known groups
    - Further investigation needed

Capability: PowerShell Empire
    - Tool: powershell.exe with encoded commands
    - TTP: Execution via WMI
    - Skill level: Intermediate

Infrastructure:
    - IP: 192.168.1.100
    - Domain: evil.com
    - C2 traffic on port 443

Victim:
    - Host: WORKSTATION-01
    - User: admin
    - Account: DOMAIN\admin
```

**Investigation Strategy**:
1. **Start with Known Vertex**: Usually Infrastructure or Capability
2. **Pivot to Other Vertices**: Use one vertex to find others
3. **Build Complete Picture**: Map all four vertices
4. **Identify Gaps**: Unknown vertices = investigation targets

**Example Pivot**:
```
Found Infrastructure: evil.com
    ↓ (pivot)
Query for: Any host connecting to evil.com
    ↓
Found Victims: WORKSTATION-01, WORKSTATION-02
    ↓ (pivot)
Query for: What tools/processes used on these hosts?
    ↓
Found Capability: PowerShell Empire, mimikatz
    ↓ (pivot)
Compare TTPs to known threat actors
    ↓
Found Adversary: TTPs match APT29
```

---

## Usage Examples

### Example 1: Basic Sigma Rule Hunt

Hunt for threats in a single EVTX file using all available Sigma rules.

```python
# Simple hunt
results = hunt_with_sigma_rules(
    evtx_path="./chainsaw/EVTX-ATTACK-SAMPLES/Lateral-Movement/sysmon-psexec.evtx"
)

# Output:
{
    "success": True,
    "total_detections": 8,
    "detections": [
        {
            "name": "PsExec Lateral Movement",
            "level": "high",
            "group": "Lateral Movement",
            "document": {
                "data": {
                    "EventID": 3,
                    "Image": "C:\\Windows\\PSEXESVC.exe",
                    ...
                }
            }
        },
        ...
    ]
}
```

---

### Example 2: Search for Specific IoC

Search for all events containing a suspicious IP address.

```python
# Search for malicious IP
results = search_ioc_in_evtx(
    evtx_path="./logs/Security.evtx",
    ioc="192.168.1.100",
    ioc_type="ip"
)

# Pyramid of Pain analysis included
{
    "success": True,
    "ioc": "192.168.1.100",
    "ioc_type": "ip",
    "pyramid_of_pain": {
        "level": 2,
        "name": "IP Addresses",
        "difficulty": "Easy",
        "priority": 5,
        "note": "Low priority - attacker can easily change IPs"
    },
    "total_matches": 15
}
```

---

### Example 3: Iterative Threat Hunting

Start with one IoC and automatically discover related indicators.

```python
# Start with suspicious domain
results = iterative_hunt(
    evtx_path="./logs/",
    initial_ioc="evil.com",
    initial_ioc_type="domain",
    max_iterations=3
)

# Workflow:
# Iteration 1: Search for "evil.com"
#   Found: 5 events
#   Discovered: IP 192.168.1.100, process "malware.exe"
#
# Iteration 2: Search for "192.168.1.100"
#   Found: 12 events
#   Discovered: Additional processes, user "compromised_user"
#
# Iteration 3: Search for "malware.exe"
#   Found: 8 events
#   Discovered: Registry keys, scheduled tasks
#
# Total: 25 events, 15 unique IoCs
```

---

### Example 4: Time-Filtered Hunt

Hunt within a specific time window.

```python
# Hunt for specific time period
results = hunt_with_sigma_rules(
    evtx_path="./logs/Security.evtx",
    from_time="2024-01-15T14:00:00",
    to_time="2024-01-15T16:00:00"
)

# Only processes events between 2 PM and 4 PM on Jan 15
```

---

### Example 5: Custom Sigma Rules

Use your own custom Sigma rules.

```python
# Use custom rules directory
results = hunt_with_sigma_rules(
    evtx_path="./logs/",
    sigma_rules_path="./my_custom_rules/",
    mapping_path="./my_custom_mapping.yml"
)
```

---

### Example 6: Event ID Filtering

Search for IoC only in specific Event IDs.

```python
# Search for process name only in process creation events
results = search_ioc_in_evtx(
    evtx_path="./logs/Security.evtx",
    ioc="powershell.exe",
    ioc_type="process_name",
    event_id=4688  # Process Creation
)
```

---

## Investigation Workflows

### Workflow 1: Suspicious Email Investigation

**Scenario**: User reported suspicious email with attachment.

**Steps**:

1. **Extract IoCs from Email**:
   ```
   Domain: evil-phishing.com
   Attachment: invoice.exe
   Hash: abc123...
   ```

2. **Search for Domain**:
   ```python
   hunt_with_sigma_rules(
       evtx_path="./logs/",
       from_time="2024-01-15T00:00:00"  # Day email received
   )
   ```

3. **Search for Attachment Execution**:
   ```python
   search_ioc_in_evtx(
       evtx_path="./logs/Security.evtx",
       ioc="invoice.exe",
       ioc_type="process_name",
       event_id=4688
   )
   ```

4. **Iterative Hunt**:
   ```python
   iterative_hunt(
       evtx_path="./logs/",
       initial_ioc="invoice.exe",
       initial_ioc_type="process_name",
       max_iterations=3
   )
   ```

5. **Analyse Results**:
   ```python
   analysis = analyze_chainsaw_results(results)
   # Check for:
   # - Credential dumping (Pyramid Level 6)
   # - Lateral movement attempts
   # - C2 communications (Diamond: Infrastructure)
   ```

---

### Workflow 2: Lateral Movement Detection

**Scenario**: Alert for suspicious RDP connection.

**Steps**:

1. **Hunt for Lateral Movement Patterns**:
   ```python
   hunt_with_sigma_rules(
       evtx_path="./logs/Security.evtx",
       from_time="now-24h"
   )
   # Look for:
   # - Event 4624 (Logon Type 10 - RDP)
   # - Event 4648 (Explicit credentials)
   # - PsExec detections
   ```

2. **Identify Source IP**:
   ```python
   # From hunt results, extract source IP: 192.168.1.50
   search_ioc_in_evtx(
       evtx_path="./logs/",
       ioc="192.168.1.50",
       ioc_type="ip"
   )
   ```

3. **Map with Diamond Model**:
   ```python
   analysis = analyze_chainsaw_results(results, analysis_type="diamond")
   # Infrastructure: Source IP 192.168.1.50
   # Capability: RDP, PsExec
   # Victim: Multiple hosts
   # Adversary: Unknown (check TTPs against known groups)
   ```

4. **Check All Affected Hosts**:
   ```python
   # For each victim host found, hunt for:
   # - Persistence mechanisms
   # - Credential dumping
   # - Data staging
   ```

---

### Workflow 3: Ransomware Investigation

**Scenario**: Files encrypted on workstation.

**Steps**:

1. **Hunt for Ransomware TTPs**:
   ```python
   hunt_with_sigma_rules(
       evtx_path="./logs/System.evtx",
       from_time="2024-01-15T00:00:00"  # Before encryption
   )
   # Look for:
   # - Mass file modifications
   # - Shadow copy deletion (vssadmin)
   # - Backup deletion
   ```

2. **Identify Initial Access**:
   ```python
   # Work backwards from encryption time
   hunt_with_sigma_rules(
       evtx_path="./logs/Security.evtx",
       from_time="2024-01-14T00:00:00",
       to_time="2024-01-15T00:00:00"
   )
   # Look for:
   # - Phishing email delivery
   # - Exploit attempts
   # - RDP brute force
   ```

3. **Iterative Hunt from Patient Zero**:
   ```python
   # Found initial process: malware.exe
   iterative_hunt(
       evtx_path="./logs/",
       initial_ioc="malware.exe",
       initial_ioc_type="process_name",
       max_iterations=5
   )
   ```

4. **Full Pyramid Analysis**:
   ```python
   analysis = analyze_chainsaw_results(all_results, analysis_type="pyramid")
   # Prioritize:
   # - Level 6 TTPs: Shadow copy deletion, mass encryption
   # - Level 5 Tools: Specific ransomware variant
   # - Level 3-1: C2 domains, IPs, hashes
   ```

5. **Scope Assessment**:
   ```python
   # Check for lateral movement to other systems
   # Identify all compromised hosts (Diamond: Victim)
   # Map full attack infrastructure (Diamond: Infrastructure)
   ```

---

### Workflow 4: Insider Threat Investigation

**Scenario**: Suspicious data access by employee.

**Steps**:

1. **Hunt for User Activity**:
   ```python
   search_ioc_in_evtx(
       evtx_path="./logs/Security.evtx",
       ioc="suspicious_user",
       ioc_type="user",
       from_time="2024-01-01T00:00:00"
   )
   ```

2. **Analyse Access Patterns**:
   ```python
   # Look for:
   # - Off-hours access
   # - Access to sensitive files/folders
   # - Large data transfers
   # - USB device usage
   # - File sharing
   ```

3. **Check for Exfiltration**:
   ```python
   hunt_with_sigma_rules(
       evtx_path="./logs/",
       from_time="user_access_time"
   )
   # Look for:
   # - Large uploads
   # - Cloud storage access
   # - Email with large attachments
   # - FTP/SFTP transfers
   ```

4. **Timeline Analysis**:
   ```python
   # Build complete timeline of user actions
   # Map to Diamond Model:
   #   Adversary: Insider (motivation?)
   #   Capability: Legitimate credentials + tools
   #   Infrastructure: Personal cloud storage?
   #   Victim: Company data/systems
   ```

---

## Best Practices

### 1. Regular Hunts

Run Sigma rule hunts regularly to catch new threats:

```python
# Daily hunt for last 24 hours
hunt_with_sigma_rules(
    evtx_path="./logs/",
    from_time="now-24h"
)
```

### 2. Prioritize by Pyramid

Always prioritize detections by Pyramid of Pain level:

```python
analysis = analyze_chainsaw_results(results)

# Focus on:
# 1. Level 6 TTPs (highest priority)
# 2. Level 5 Tools
# 3. Level 4 Artifacts
# ... lower levels for context only
```

### 3. Use Diamond Model for Context

Map findings to Diamond Model to understand full attack:

```python
# Don't just block an IP (Infrastructure)
# Understand:
# - What tool was used? (Capability)
# - Who was targeted? (Victim)
# - Does TTP match known adversary? (Adversary)
```

### 4. Iterative Hunting for Complex Attacks

Use iterative hunting for APT-style investigations:

```python
# APT attacks leave many IoCs
# Start with one, discover all related indicators
iterative_hunt(
    initial_ioc="apt_c2_domain.com",
    initial_ioc_type="domain",
    max_iterations=5  # Deep dive
)
```

### 5. Time Windows

Always use time filtering to reduce noise:

```python
# Incident occurred at 2024-01-15 14:30
# Search +/- 2 hours
hunt_with_sigma_rules(
    evtx_path="./logs/",
    from_time="2024-01-15T12:30:00",
    to_time="2024-01-15T16:30:00"
)
```

### 6. Custom Sigma Rules

Create custom rules for your environment:

```yaml
# ./chainsaw/rules/my_custom_rule.yml
title: Suspicious Process in Custom App Dir
description: Detects execution in custom application directory
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4688
        NewProcessName|contains: 'C:\CustomApp\'
    condition: selection
level: medium
```

```python
hunt_with_sigma_rules(
    evtx_path="./logs/",
    custom_rules_path="./chainsaw/rules/"
)
```

### 7. Combine with Elasticsearch

Use Chainsaw for Windows logs, Elasticsearch for everything else:

```python
# 1. Hunt EVTX files with Chainsaw
evtx_results = hunt_with_sigma_rules(evtx_path="./logs/")

# 2. Extract IoCs
iocs = extract_iocs_from_results(evtx_results)

# 3. Hunt same IoCs in Elasticsearch (Linux, network logs)
for ioc in iocs:
    es_results = hunt_for_ioc(
        index="logs-*",
        ioc_type=ioc["type"],
        ioc_value=ioc["value"]
    )

# 4. Complete cross-platform investigation
```

### 8. Automate Regular Tasks

Create scripts for common hunting tasks:

```python
# daily_hunt.py
def daily_threat_hunt():
    # Hunt in all EVTX files
    results = hunt_with_sigma_rules(
        evtx_path="/var/logs/evtx/",
        from_time="now-24h"
    )

    # Analyse with both frameworks
    analysis = analyze_chainsaw_results(results, analysis_type="both")

    # Alert on high-priority findings
    if analysis["pyramid_analysis"]["level_6_ttps"]:
        send_alert("High priority TTPs detected!")

    return analysis
```

### 9. Maintain Sigma Rules

Keep Sigma rules updated:

```bash
# Update Sigma rules monthly
cd chainsaw/sigma
git pull origin master
```

### 10. Document Findings

Always document using both frameworks:

```
Investigation: Suspicious Activity on WORKSTATION-01
Date: 2024-01-15

Pyramid of Pain Analysis:
- Level 6 (TTPs): Credential Dumping via LSASS
- Level 5 (Tools): Mimikatz detected
- Level 3 (Domain): C2 domain evil.com
- Level 2 (IP): C2 IP 192.168.1.100
- Level 1 (Hash): malware.exe hash abc123...

Diamond Model Mapping:
- Adversary: Unknown (TTPs similar to APT29)
- Capability: Mimikatz, PowerShell Empire, WMI
- Infrastructure: evil.com, 192.168.1.100
- Victim: WORKSTATION-01, user "admin"

Recommendations:
1. Block evil.com and 192.168.1.100 (short-term)
2. Create detection for LSASS credential dumping (long-term)
3. Hunt for lateral movement from WORKSTATION-01
4. Reset credentials for user "admin"
```

---

## Troubleshooting

### Chainsaw Binary Not Found

**Error**: `Chainsaw not installed`

**Solution**:
```bash
# Re-run setup
./setup.sh

# Or manually install
cd chainsaw
curl -L -o chainsaw.zip https://github.com/WithSecureLabs/chainsaw/releases/latest/download/chainsaw_all_platforms+rules+examples.zip
unzip chainsaw.zip
chmod +x chainsaw/chainsaw_x86_64-unknown-linux-gnu
mv chainsaw/chainsaw_x86_64-unknown-linux-gnu chainsaw
```

### Sigma Rules Not Found

**Error**: `Sigma rules directory not found`

**Solution**:
```bash
cd chainsaw
git clone --depth 1 --filter=blob:none --sparse https://github.com/SigmaHQ/sigma.git sigma_temp
cd sigma_temp
git sparse-checkout set rules
cd ..
mv sigma_temp/rules sigma
rm -rf sigma_temp
```

### No Detections Found

**Possible Causes**:
1. **No threats in logs**: Logs may be clean
2. **Wrong time range**: Adjust `from_time` and `to_time`
3. **Wrong Sigma rules**: Try different rule sets
4. **Mapping issues**: Check mapping file

**Solution**:
```python
# Test with sample EVTX files
hunt_with_sigma_rules(
    evtx_path="./chainsaw/EVTX-ATTACK-SAMPLES/Lateral-Movement/sysmon-psexec.evtx"
)
# Should detect PsExec lateral movement
```

### Permission Denied

**Error**: `Permission denied: ./chainsaw/chainsaw`

**Solution**:
```bash
chmod +x chainsaw/chainsaw
```

### JSON Parse Error

**Error**: `Failed to parse JSON output`

**Cause**: Chainsaw output may contain warnings mixed with JSON

**Solution**:
```python
# Use quiet mode (automatic in hunt_with_sigma_rules)
hunt_with_sigma_rules(evtx_path="./logs/")
# Internally uses: chainsaw hunt ... --json -q
```

### Out of Memory

**Error**: Large EVTX files cause memory issues

**Solution**:
```python
# Process files individually instead of directory
for evtx_file in evtx_files:
    results = hunt_with_sigma_rules(evtx_path=evtx_file)
    process_results(results)
```

---

## Quick Reference

### Common Commands

```python
# Basic hunt
hunt_with_sigma_rules(evtx_path="./logs/Security.evtx")

# Search for IP
search_ioc_in_evtx(
    evtx_path="./logs/",
    ioc="192.168.1.100",
    ioc_type="ip"
)

# Iterative hunt
iterative_hunt(
    evtx_path="./logs/",
    initial_ioc="evil.com",
    initial_ioc_type="domain"
)

# Time-filtered hunt
hunt_with_sigma_rules(
    evtx_path="./logs/",
    from_time="2024-01-15T14:00:00",
    to_time="2024-01-15T16:00:00"
)

# Get frameworks
get_pyramid_of_pain_guide()
get_diamond_model_guide()

# Analyse results
analyze_chainsaw_results(results)
```

### IoC Types

| Type | Examples | Pyramid Level |
|------|----------|---------------|
| `hash` | MD5, SHA1, SHA256 | 1 (Trivial) |
| `ip` | 192.168.1.100 | 2 (Easy) |
| `domain` | evil.com | 3 (Simple) |
| `url` | http://evil.com/malware | 3 (Simple) |
| `user_agent` | Mozilla/5.0... | 4 (Annoying) |
| `registry_key` | HKLM\...\Run | 4 (Annoying) |
| `file_path` | C:\Temp\malware.exe | 4 (Annoying) |
| `process_name` | mimikatz.exe | 5 (Challenging) |
| `tool` | psexec, cobalt strike | 5 (Challenging) |
| `ttp` | Credential Dumping | 6 (Tough) |

### Important Event IDs

| Event ID | Description | Category |
|----------|-------------|----------|
| 4624 | Successful Logon | Authentication |
| 4625 | Failed Logon | Authentication |
| 4648 | Logon with Explicit Credentials | Lateral Movement |
| 4672 | Special Privileges Assigned | Privilege Escalation |
| 4688 | Process Creation | Execution |
| 4697 | Service Installed | Persistence |
| 4698 | Scheduled Task Created | Persistence |
| 4720 | User Account Created | Persistence |
| 4732 | Member Added to Security Group | Privilege Escalation |
| 5156 | Windows Filtering Platform Connection | Network |

### Directory Structure

```
chainsaw/
├── chainsaw                  # Binary
├── sigma/                    # Sigma rules
│   ├── windows/
│   │   ├── process_creation/
│   │   ├── network_connection/
│   │   └── ...
│   ├── linux/
│   └── cloud/
├── mappings/                 # Field mappings
│   └── sigma-event-logs-all.yml
├── rules/                    # Custom rules
├── EVTX-ATTACK-SAMPLES/     # Sample files
│   ├── Lateral-Movement/
│   ├── Credential-Access/
│   └── ...
```

---

## Summary

The Chainsaw integration provides powerful Windows Event Log hunting capabilities with:

✅ **6 MCP Tools** for hunting and analysis
✅ **Pyramid of Pain** framework for IoC prioritisation
✅ **Diamond Model** for comprehensive attack mapping
✅ **3,000+ Sigma Rules** for threat detection
✅ **Iterative Hunting** for complex investigations
✅ **Sample EVTX Files** for testing and training
✅ **Time Filtering** for focused investigations
✅ **Automated Setup** via setup.sh

**Next Steps**:
1. Run `./setup.sh` to install Chainsaw
2. Test with sample EVTX files in `chainsaw/EVTX-ATTACK-SAMPLES/`
3. Try the investigation workflows
4. Integrate with your Elasticsearch threat hunting workflows

For more information:
- **Chainsaw**: https://github.com/WithSecureLabs/chainsaw
- **Sigma Rules**: https://github.com/SigmaHQ/sigma
- **Pyramid of Pain**: http://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html
- **Diamond Model**: https://www.activeresponse.org/the-diamond-model/

---

**Document Version**: 1.0
**Last Updated**: 2025-12-21
**MCP Server Version**: 0.2.2
