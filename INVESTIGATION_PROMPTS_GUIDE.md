# Investigation Prompts Guide

## Overview

The Investigation Prompts system provides **10 pre-built triage questions** designed for rapid incident response and threat hunting. These questions form the "fast triage spine" that every security analyst should ask when investigating a potential security incident.

### The Triage Spine Methodology

The prompts follow a systematic investigation flow:
1. **Identity** → Who accessed the system?
2. **Execution** → What processes/commands were executed?
3. **Persistence** → What persistence mechanisms were created?
4. **Network** → What network connections were established?
5. **Privilege** → What privilege escalations occurred?

### Platform Coverage

- **5 Linux Investigation Prompts** - Covering auth.log, auditd, sshd, sudo, and system logs
- **5 Windows Investigation Prompts** - Covering Security Event Logs, PowerShell, Sysmon

---

## Available MCP Tools

The investigation prompts system provides 5 MCP tools:

### 1. `show_investigation_prompts`

Display all available investigation triage questions.

**Parameters:**
- `platform` (optional): Filter by "linux" or "windows" (None shows both)
- `show_details` (bool): Show detailed information including log sources and fields

**Example:**
```python
# Show all prompts
show_investigation_prompts()

# Show only Windows prompts
show_investigation_prompts(platform="windows")

# Show with full details
show_investigation_prompts(platform="linux", show_details=True)
```

**Returns:**
```json
{
  "message": "Investigation Triage Spine - First Questions for SIEM/SOAR",
  "total_prompts": 10,
  "linux_prompts": { ... },
  "windows_prompts": { ... },
  "usage_tip": "Use start_guided_investigation() to begin investigating"
}
```

---

### 2. `investigate_with_prompt`

Execute a specific investigation prompt against your Elasticsearch logs.

**Parameters:**
- `prompt_id` (required): Investigation prompt ID
- `index` (required): Index pattern to search (e.g., "winlogbeat-*", "auditbeat-*")
- `timeframe_minutes` (optional): Time window in minutes (default: 60)
- `size` (optional): Maximum number of results (default: 100, max: 500)
- `host` (optional): Filter by specific hostname
- `username` (optional): Filter by specific username
- `source_ip` (optional): Filter by specific source IP

**Linux Prompt IDs:**
- `linux_auth_1` - Who authenticated and how?
- `linux_privilege_2` - Privilege escalation via sudo/su
- `linux_processes_3` - Unusual process execution
- `linux_persistence_4` - Persistence mechanisms
- `linux_network_5` - Outbound network connections

**Windows Prompt IDs:**
- `windows_logon_1` - Logon activity analysis
- `windows_processes_2` - Process creation events
- `windows_powershell_3` - PowerShell execution analysis
- `windows_persistence_4` - Persistence mechanisms
- `windows_privilege_5` - Privilege escalation attempts

**Examples:**

```python
# Investigate Windows logons for a specific host
investigate_with_prompt(
    prompt_id="windows_logon_1",
    index="winlogbeat-*",
    timeframe_minutes=120,
    host="WEB-SERVER-01"
)

# Investigate Linux privilege escalation for a user
investigate_with_prompt(
    prompt_id="linux_privilege_2",
    index="auditbeat-*",
    username="admin",
    timeframe_minutes=60
)

# Investigate PowerShell execution
investigate_with_prompt(
    prompt_id="windows_powershell_3",
    index="winlogbeat-*",
    timeframe_minutes=240
)
```

**Returns:**
```json
{
  "prompt_id": "windows_logon_1",
  "platform": "WINDOWS",
  "priority": 1,
  "question": "Who logged on, from where, and using what logon type?",
  "description": "...",
  "total_hits": 42,
  "events": [ ... ],
  "focus_areas": [ ... ],
  "mitre_tactics": ["initial_access", "persistence"],
  "timeframe_minutes": 120
}
```

---

### 3. `start_guided_investigation`

Start a comprehensive guided investigation using all triage prompts for a platform.

**Parameters:**
- `platform` (required): Target platform ("linux" or "windows")
- `index` (required): Index pattern to search
- `timeframe_minutes` (optional): Investigation window in minutes (default: 60)
- `host` (optional): Filter by hostname

**Examples:**

```python
# Investigate Windows endpoint
start_guided_investigation(
    platform="windows",
    index="winlogbeat-*",
    timeframe_minutes=120,
    host="DESKTOP-ABC123"
)

# Investigate Linux server
start_guided_investigation(
    platform="linux",
    index="auditbeat-*",
    timeframe_minutes=60,
    host="web-server-01"
)
```

**Returns:**
```json
{
  "platform": "WINDOWS",
  "index": "winlogbeat-*",
  "timeframe_minutes": 120,
  "host_filter": "DESKTOP-ABC123",
  "total_prompts": 5,
  "total_findings": 87,
  "investigation_results": [
    {
      "prompt_id": "windows_logon_1",
      "total_hits": 23,
      "events": [ ... ]
    },
    ...
  ],
  "summary": "⚠ Found 87 events requiring investigation"
}
```

---

### 4. `quick_triage`

Fast initial assessment using top N priority prompts.

**Parameters:**
- `platform` (required): Target platform ("linux" or "windows")
- `index` (required): Index pattern to search
- `host` (required): Hostname to investigate
- `timeframe_minutes` (optional): Investigation window (default: 60)
- `top_n_prompts` (optional): Number of prompts to run (default: 3, max: 5)

**Examples:**

```python
# Quick Windows triage
quick_triage(
    platform="windows",
    index="winlogbeat-*",
    host="DESKTOP-ABC123",
    timeframe_minutes=120
)

# Quick Linux triage with top 5 prompts
quick_triage(
    platform="linux",
    index="auditbeat-*",
    host="web-server-01",
    top_n_prompts=5
)
```

**Returns:**
```json
{
  "triage_type": "QUICK TRIAGE",
  "platform": "WINDOWS",
  "host": "DESKTOP-ABC123",
  "timeframe_minutes": 120,
  "prompts_executed": 3,
  "total_findings": 15,
  "findings": [
    {
      "priority": 1,
      "question": "Who logged on, from where...",
      "hits": 8,
      "top_events": [ ... ],
      "prompt_id": "windows_logon_1"
    }
  ],
  "assessment": "⚠ ALERT - 15 suspicious events found",
  "recommendation": "Review findings and run start_guided_investigation() for comprehensive analysis"
}
```

---

### 5. `get_investigation_query`

Get the Elasticsearch query template for an investigation prompt.

**Parameters:**
- `prompt_id` (required): Investigation prompt ID

**Example:**
```python
get_investigation_query("windows_logon_1")
```

**Returns:**
```json
{
  "prompt_id": "windows_logon_1",
  "platform": "WINDOWS",
  "priority": 1,
  "question": "Who logged on, from where, and using what logon type?",
  "description": "...",
  "query_template": "event.code:(4624 OR 4625 OR 4634 OR 4647 OR 4648)",
  "log_sources_required": [
    "Security 4624 (successful logon)",
    "Security 4625 (failed logon)",
    ...
  ],
  "elasticsearch_fields": [
    "winlog.event_data.TargetUserName",
    "winlog.event_data.TargetDomainName",
    ...
  ],
  "focus_areas": [ ... ],
  "mitre_tactics": ["initial_access", "persistence"],
  "usage": "investigate_with_prompt(prompt_id='windows_logon_1', index='your-index-*')"
}
```

---

## Investigation Prompts Details

### Linux Prompts

#### 1. `linux_auth_1` - Authentication Analysis (Priority 1)
**Question:** Who authenticated to the box during the suspected window, from where, and how?

**Focus Areas:**
- Successful SSH logins
- Failed SSH login attempts
- Source IP addresses and geolocation
- Authentication methods used

**Log Sources:**
- /var/log/auth.log (SSH events)
- /var/log/secure
- auditd authentication events

**Key Fields:**
- `system.auth.ssh.event`
- `source.ip`, `source.geo.country_name`
- `user.name`
- `event.action`

**MITRE ATT&CK:** Initial Access, Valid Accounts

---

#### 2. `linux_privilege_2` - Privilege Escalation (Priority 2)
**Question:** Did anyone gain root via sudo/su, and exactly what commands did they run?

**Focus Areas:**
- Sudo command execution
- Su privilege escalation
- Root access patterns
- Command history for privileged users

**Log Sources:**
- /var/log/auth.log (sudo/su events)
- auditd privilege escalation
- /var/log/sudo.log

**Key Fields:**
- `process.name` (sudo, su)
- `user.name`, `user.effective.name`
- `process.args`
- `event.action`

**MITRE ATT&CK:** Privilege Escalation, Valid Accounts

---

#### 3. `linux_processes_3` - Process Execution (Priority 3)
**Question:** What new or unusual processes executed (and from which paths)?

**Focus Areas:**
- Unusual process execution paths
- Process command lines
- Parent-child process relationships
- Execution from temp directories

**Log Sources:**
- auditd process execution events
- System process logs
- execve() audit events

**Key Fields:**
- `process.name`, `process.executable`
- `process.args`, `process.command_line`
- `process.parent.name`
- `file.path`

**MITRE ATT&CK:** Execution, Command and Scripting Interpreter

---

#### 4. `linux_persistence_4` - Persistence Mechanisms (Priority 4)
**Question:** What persistence changed on the host, and who changed it?

**Focus Areas:**
- Cron job modifications
- systemd service changes
- /etc/rc.local modifications
- User account creation

**Log Sources:**
- auditd file modification events
- systemd journal
- crontab logs

**Key Fields:**
- `file.path` (/etc/crontab, /etc/systemd/*, .bashrc)
- `user.name`
- `event.action` (file_create, file_modify)
- `process.name`

**MITRE ATT&CK:** Persistence, Scheduled Task/Job

---

#### 5. `linux_network_5` - Network Activity (Priority 5)
**Question:** What outbound network connections did the host initiate, and to where?

**Focus Areas:**
- Outbound connections
- Unusual destination IPs/ports
- Data exfiltration indicators
- Command and control traffic

**Log Sources:**
- auditd network events
- netflow/packetbeat
- firewall logs

**Key Fields:**
- `destination.ip`, `destination.port`
- `destination.geo.country_name`
- `network.protocol`
- `process.name`

**MITRE ATT&CK:** Command and Control, Exfiltration

---

### Windows Prompts

#### 1. `windows_logon_1` - Logon Activity (Priority 1)
**Question:** Who logged on, from where, and using what logon type—and what changed vs baseline?

**Focus Areas:**
- Logon type analysis (Interactive, Network, RemoteInteractive)
- Failed logon attempts
- Source workstation/IP
- Logoff events

**Log Sources:**
- Security 4624 (successful logon)
- Security 4625 (failed logon)
- Security 4634/4647 (logoff)
- Security 4648 (explicit credential use)

**Key Fields:**
- `winlog.event_data.TargetUserName`
- `winlog.event_data.LogonType`
- `winlog.event_data.WorkstationName`
- `winlog.event_data.IpAddress`

**MITRE ATT&CK:** Initial Access, Valid Accounts, Lateral Movement

---

#### 2. `windows_processes_2` - Process Creation (Priority 2)
**Question:** What processes spawned around the alert, with full command lines and parent chains?

**Focus Areas:**
- Process creation events
- Command line arguments
- Parent-child relationships
- Suspicious process paths

**Log Sources:**
- Security 4688 (process creation)
- Sysmon Event ID 1 (process creation)

**Key Fields:**
- `winlog.event_data.NewProcessName`
- `winlog.event_data.CommandLine`
- `winlog.event_data.ParentProcessName`
- `winlog.event_data.SubjectUserName`

**MITRE ATT&CK:** Execution, Process Injection

---

#### 3. `windows_powershell_3` - PowerShell Activity (Priority 3)
**Question:** Was PowerShell used, and was it doing anything sketchy (encoded commands, downloads)?

**Focus Areas:**
- PowerShell command execution
- Base64 encoded commands
- DownloadString/DownloadFile usage
- Script block logging

**Log Sources:**
- PowerShell 4104 (script block logging)
- Security 4688 (powershell.exe execution)
- Sysmon Event ID 1 (PowerShell processes)

**Key Fields:**
- `winlog.event_data.ScriptBlockText`
- `winlog.event_data.CommandLine`
- `process.name` (powershell.exe)

**MITRE ATT&CK:** Execution, Command and Scripting Interpreter

---

#### 4. `windows_persistence_4` - Persistence (Priority 4)
**Question:** What persistence was created or modified (services/tasks/Run keys)?

**Focus Areas:**
- Service installation
- Scheduled task creation
- Registry Run key modifications
- Startup folder changes

**Log Sources:**
- System 7045 (service installed)
- Security 4698 (scheduled task created)
- Security 4702 (scheduled task updated)
- Sysmon Event ID 13 (registry modification)

**Key Fields:**
- `winlog.event_data.ServiceName`
- `winlog.event_data.TaskName`
- `winlog.event_data.TargetObject` (registry)

**MITRE ATT&CK:** Persistence, Scheduled Task/Job, Boot or Logon Autostart Execution

---

#### 5. `windows_privilege_5` - Privilege Escalation (Priority 5)
**Question:** Any signs of privilege/credential access—and how far did it spread?

**Focus Areas:**
- Special privileges assigned
- Credential dumping indicators
- Token manipulation
- LSASS access

**Log Sources:**
- Security 4672 (special privileges assigned)
- Security 4673 (sensitive privilege use)
- Sysmon Event ID 10 (process access to LSASS)

**Key Fields:**
- `winlog.event_data.PrivilegeList`
- `winlog.event_data.TargetImage` (lsass.exe)
- `winlog.event_data.SourceImage`

**MITRE ATT&CK:** Privilege Escalation, Credential Access

---

## Typical Investigation Workflows

### Workflow 1: Initial Triage (5 minutes)

When you first receive an alert:

```python
# Step 1: Quick triage to get initial assessment
quick_triage(
    platform="windows",
    index="winlogbeat-*",
    host="suspicious-host",
    timeframe_minutes=120,
    top_n_prompts=3
)

# Review the assessment and top findings
# If suspicious activity found → proceed to full investigation
```

---

### Workflow 2: Comprehensive Investigation (15-30 minutes)

For confirmed or high-severity incidents:

```python
# Step 1: Run full guided investigation
start_guided_investigation(
    platform="windows",
    index="winlogbeat-*",
    timeframe_minutes=240,
    host="compromised-host"
)

# Step 2: Deep dive into specific areas showing activity
investigate_with_prompt(
    prompt_id="windows_powershell_3",
    index="winlogbeat-*",
    timeframe_minutes=480,
    host="compromised-host"
)

# Step 3: Investigate related hosts/users found in Step 2
investigate_with_prompt(
    prompt_id="windows_logon_1",
    index="winlogbeat-*",
    username="suspicious_user",
    timeframe_minutes=720
)
```

---

### Workflow 3: Targeted Investigation

When you have specific indicators:

```python
# Investigate a specific username
investigate_with_prompt(
    prompt_id="linux_auth_1",
    index="auditbeat-*",
    username="hacker123",
    timeframe_minutes=1440  # 24 hours
)

# Investigate a specific source IP
investigate_with_prompt(
    prompt_id="windows_logon_1",
    index="winlogbeat-*",
    source_ip="203.0.113.42",
    timeframe_minutes=2880  # 48 hours
)
```

---

## Best Practices

### 1. **Start with Quick Triage**
Always begin with `quick_triage()` for rapid assessment before deep investigation.

### 2. **Adjust Timeframes Appropriately**
- Alerts < 1 hour old: 60-120 minutes
- Historical investigation: 24-48 hours (1440-2880 minutes)
- Persistence hunting: 7-30 days

### 3. **Use Filters to Narrow Results**
Combine host, username, and source_ip filters to focus investigation:

```python
investigate_with_prompt(
    prompt_id="windows_processes_2",
    index="winlogbeat-*",
    host="target-host",
    username="compromised_user",
    timeframe_minutes=240
)
```

### 4. **Follow the Kill Chain**
Investigate in order:
1. Identity (how did they get in?)
2. Execution (what did they run?)
3. Persistence (how are they staying?)
4. Network (where are they going?)
5. Privilege (how far did they get?)

### 5. **Review Query Templates**
Use `get_investigation_query()` to understand what each prompt is looking for:

```python
get_investigation_query("windows_persistence_4")
```

### 6. **Size Limits**
- Quick triage: 20 events per prompt (fast)
- Normal investigation: 100 events per prompt
- Deep dive: 500 events maximum

---

## Integration with Detection Rules

Investigation prompts work alongside the detection rules system:

```python
# Step 1: Execute detection rules to find threats
execute_detection_rule(
    rule_id="windows_credential_mimikatz",
    index="winlogbeat-*",
    timeframe_minutes=60
)

# Step 2: If detections fire, use investigation prompts for context
investigate_with_prompt(
    prompt_id="windows_privilege_5",
    index="winlogbeat-*",
    timeframe_minutes=120
)

# Step 3: Use guided investigation for full scope
start_guided_investigation(
    platform="windows",
    index="winlogbeat-*",
    timeframe_minutes=240
)
```

---

## Customising Investigation Prompts

The prompts are defined in `src/clients/common/investigation_prompts.py`.

Each prompt can be customised by modifying:
- `query_template` - The Elasticsearch query
- `elasticsearch_fields` - Fields to focus on
- `focus_areas` - What to look for
- `log_sources` - Required log types

Example prompt structure:
```python
InvestigationPrompt(
    id="custom_prompt_1",
    platform="windows",
    priority=1,
    question="Your investigation question?",
    description="Detailed description",
    focus_areas=["area1", "area2"],
    log_sources=["log_source_1"],
    elasticsearch_fields=["field1", "field2"],
    query_template="event.code:1234",
    mitre_tactics=["tactic1"]
)
```

---

## Troubleshooting

### No Results Found

**Possible causes:**
1. Timeframe too narrow - increase `timeframe_minutes`
2. Wrong index pattern - verify with your Elasticsearch admin
3. Field names don't match - check your log format
4. Logs not being collected for that host

**Solution:**
```python
# Try broader timeframe
investigate_with_prompt(
    prompt_id="windows_logon_1",
    index="*",  # Search all indices
    timeframe_minutes=2880,  # 48 hours
    host="target-host"
)
```

### Too Many Results

**Solution:**
```python
# Add more filters
investigate_with_prompt(
    prompt_id="windows_processes_2",
    index="winlogbeat-*",
    timeframe_minutes=60,  # Narrow timeframe
    host="specific-host",  # Add host filter
    username="specific-user",  # Add user filter
    size=50  # Limit results
)
```

### Query Syntax Errors

Use `get_investigation_query()` to review the query template and adjust field names for your environment.

---

## Quick Reference Card

### Linux Investigation
```python
# Quick triage
quick_triage("linux", "auditbeat-*", "web-server-01", 60, 3)

# Full investigation
start_guided_investigation("linux", "auditbeat-*", 120, "web-server-01")

# Specific prompts
investigate_with_prompt("linux_auth_1", "auditbeat-*", 60, host="server")
investigate_with_prompt("linux_privilege_2", "auditbeat-*", 120, username="admin")
investigate_with_prompt("linux_processes_3", "auditbeat-*", 240)
investigate_with_prompt("linux_persistence_4", "auditbeat-*", 1440)
investigate_with_prompt("linux_network_5", "auditbeat-*", 60)
```

### Windows Investigation
```python
# Quick triage
quick_triage("windows", "winlogbeat-*", "DESKTOP-01", 60, 3)

# Full investigation
start_guided_investigation("windows", "winlogbeat-*", 120, "DESKTOP-01")

# Specific prompts
investigate_with_prompt("windows_logon_1", "winlogbeat-*", 60, host="PC")
investigate_with_prompt("windows_processes_2", "winlogbeat-*", 120, username="user")
investigate_with_prompt("windows_powershell_3", "winlogbeat-*", 240)
investigate_with_prompt("windows_persistence_4", "winlogbeat-*", 1440)
investigate_with_prompt("windows_privilege_5", "winlogbeat-*", 60)
```

---

## See Also

- [Detection Rules Guide](DETECTION_RULES_GUIDE.md) - Automated threat detection
- [README.md](README.md) - General server documentation
- [Threat Hunting Tools](src/tools/threat_hunting.py) - Additional hunting capabilities

---

**Last Updated:** 2025-12-21
**Version:** 1.0
