# MITRE ATT&CK Framework Reference

## Overview

MITRE ATT&CK (Adversarial Tactics, Techniques, and Common Knowledge) is a knowledge base of adversary tactics and techniques based on real-world observations.

## Tactics (The "Why")

Tactics represent the adversary's tactical goals - the reason for performing an action.

| ID | Tactic | Description | CrowdSentinel Tool |
|----|--------|-------------|-------------------|
| TA0043 | Reconnaissance | Gathering information | `search_rules_by_mitre_attack(tactic="reconnaissance")` |
| TA0042 | Resource Development | Establishing resources | N/A (pre-compromise) |
| TA0001 | Initial Access | Getting into the network | `hunt_by_kill_chain_stage(stage="DELIVERY")` |
| TA0002 | Execution | Running malicious code | `search_rules_by_mitre_attack(tactic="execution")` |
| TA0003 | Persistence | Maintaining foothold | `search_rules_by_mitre_attack(tactic="persistence")` |
| TA0004 | Privilege Escalation | Gaining higher permissions | `search_rules_by_mitre_attack(tactic="privilege_escalation")` |
| TA0005 | Defence Evasion | Avoiding detection | `search_rules_by_mitre_attack(tactic="defense_evasion")` |
| TA0006 | Credential Access | Stealing credentials | `search_rules_by_mitre_attack(tactic="credential_access")` |
| TA0007 | Discovery | Learning the environment | `search_rules_by_mitre_attack(tactic="discovery")` |
| TA0008 | Lateral Movement | Moving through network | `search_rules_by_mitre_attack(tactic="lateral_movement")` |
| TA0009 | Collection | Gathering target data | `search_rules_by_mitre_attack(tactic="collection")` |
| TA0011 | Command and Control | Communicating with systems | `search_rules_by_mitre_attack(tactic="command_and_control")` |
| TA0010 | Exfiltration | Stealing data | `search_rules_by_mitre_attack(tactic="exfiltration")` |
| TA0040 | Impact | Manipulating/destroying systems | `search_rules_by_mitre_attack(tactic="impact")` |

## Common Techniques by Tactic

### Execution (TA0002)

| Technique | ID | Detection Rule Search |
|-----------|----|-----------------------|
| Command and Scripting Interpreter | T1059 | `list_detection_rules(search_term="scripting")` |
| PowerShell | T1059.001 | `list_detection_rules(search_term="powershell")` |
| Windows Command Shell | T1059.003 | `list_detection_rules(search_term="cmd.exe")` |
| Scheduled Task/Job | T1053 | `list_detection_rules(search_term="scheduled task")` |
| Windows Management Instrumentation | T1047 | `list_detection_rules(search_term="wmi")` |

### Persistence (TA0003)

| Technique | ID | Detection Rule Search |
|-----------|----|-----------------------|
| Registry Run Keys | T1547.001 | `list_detection_rules(search_term="run key")` |
| Scheduled Task | T1053.005 | `list_detection_rules(search_term="schtasks")` |
| Create Account | T1136 | `list_detection_rules(search_term="create account")` |
| Boot or Logon Autostart | T1547 | `list_detection_rules(search_term="autostart")` |
| Windows Service | T1543.003 | `list_detection_rules(search_term="service create")` |

### Credential Access (TA0006)

| Technique | ID | Detection Rule Search |
|-----------|----|-----------------------|
| OS Credential Dumping | T1003 | `list_detection_rules(search_term="credential dump")` |
| LSASS Memory | T1003.001 | `list_detection_rules(search_term="lsass")` |
| Brute Force | T1110 | `analyze_failed_logins()` |
| Credentials from Password Stores | T1555 | `list_detection_rules(search_term="password store")` |

### Lateral Movement (TA0008)

| Technique | ID | Detection Rule Search |
|-----------|----|-----------------------|
| Remote Services | T1021 | `list_detection_rules(search_term="remote service")` |
| SMB/Windows Admin Shares | T1021.002 | `list_detection_rules(search_term="smb")` |
| Remote Desktop Protocol | T1021.001 | `list_detection_rules(search_term="rdp")` |
| Pass the Hash | T1550.002 | `list_detection_rules(search_term="pass the hash")` |

### Command and Control (TA0011)

| Technique | ID | Detection Rule Search |
|-----------|----|-----------------------|
| Application Layer Protocol | T1071 | `list_detection_rules(search_term="c2")` |
| Web Protocols | T1071.001 | `list_detection_rules(search_term="http beacon")` |
| DNS | T1071.004 | `list_detection_rules(search_term="dns tunnel")` |
| Encrypted Channel | T1573 | `list_detection_rules(search_term="encrypted")` |

## CrowdSentinel Integration

### Automatic MITRE Mapping

```python
# analyze_search_results automatically maps to MITRE
analysis = analyze_search_results(
    search_results=results,
    context="PowerShell execution investigation"
)
# Returns: mitre_techniques: ["T1059.001", ...]
```

### Search Rules by MITRE

```python
# Find all credential access rules
rules = search_rules_by_mitre_attack(
    tactic="credential_access",
    platform="windows"
)

# Execute matching rules
for rule in rules["rules"]:
    execute_detection_rule(
        rule_id=rule["id"],
        index="winlogbeat-*",
        timeframe_minutes=1440
    )
```

### Kill Chain to MITRE Mapping

| Kill Chain Stage | Primary MITRE Tactics |
|------------------|----------------------|
| Reconnaissance | TA0043 Reconnaissance |
| Weaponisation | TA0042 Resource Development |
| Delivery | TA0001 Initial Access |
| Exploitation | TA0002 Execution |
| Installation | TA0003 Persistence, TA0004 Privilege Escalation |
| Command & Control | TA0011 Command and Control |
| Actions on Objectives | TA0009 Collection, TA0010 Exfiltration, TA0040 Impact |

## Resources

- MITRE ATT&CK Website: https://attack.mitre.org/
- ATT&CK Navigator: https://mitre-attack.github.io/attack-navigator/
- ATT&CK Data Sources: https://attack.mitre.org/datasources/
