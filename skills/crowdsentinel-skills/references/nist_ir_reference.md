# NIST Incident Response Framework Reference

## Overview

The NIST Incident Response (IR) framework provides a structured approach to handling security incidents. Based on NIST SP 800-61 Rev 2 "Computer Security Incident Handling Guide".

## IR Lifecycle Phases

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                                                                             │
│   ┌──────────────┐                                                          │
│   │ PREPARATION  │                                                          │
│   └──────┬───────┘                                                          │
│          │                                                                  │
│          ▼                                                                  │
│   ┌──────────────┐    ┌──────────────┐    ┌──────────────────────────────┐ │
│   │  DETECTION   │───▶│   ANALYSIS   │───▶│ CONTAINMENT/ERADICATION/    │ │
│   │& ANALYSIS    │    │              │    │ RECOVERY                     │ │
│   └──────────────┘    └──────────────┘    └──────────────┬───────────────┘ │
│          ▲                                               │                  │
│          │                                               │                  │
│          │            ┌──────────────────────────────────┘                  │
│          │            │                                                     │
│          │            ▼                                                     │
│          │     ┌──────────────────┐                                        │
│          └─────│ POST-INCIDENT    │                                        │
│                │ ACTIVITY         │                                        │
│                └──────────────────┘                                        │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Phase 1: Preparation

**Objective**: Establish capability to respond to incidents.

### CrowdSentinel Preparation Tasks

| Task | Tool | Command |
|------|------|---------|
| Verify data sources | `discover_all_assets()` | Check available indices |
| Test connectivity | `get_cluster_health()` | Verify ES connection |
| Review detection rules | `get_rule_statistics()` | Understand rule coverage |
| Set up investigation tracking | `create_investigation()` | Create investigation template |

```python
# Preparation checklist
assets = discover_all_assets()
health = get_cluster_health()
stats = get_rule_statistics()

print(f"Data sources: {len(assets.get('indices', []))}")
print(f"Detection rules: {stats.get('total_rules', 0)}")
print(f"Cluster status: {health.get('status')}")
```

## Phase 2: Detection and Analysis

**Objective**: Identify and understand the incident.

### Detection Methods

| Method | CrowdSentinel Tool | Use Case |
|--------|-------------------|----------|
| Rule-based detection | `execute_detection_rule()` | Known attack patterns |
| Behavioural analysis | `hunt_by_timeframe()` | Anomaly detection |
| IoC hunting | `hunt_for_ioc()` | Indicator search |
| Timeline analysis | `get_host_activity_timeline()` | Forensic analysis |

### Analysis Workflow

```python
# Step 1: Initial detection
results = execute_detection_rule(
    rule_id="windows_process_creation_susp_powershell_eql",
    index="winlogbeat-*",
    timeframe_minutes=1440
)

# Step 2: Analyse findings
analysis = analyze_search_results(
    search_results=results,
    context="Suspicious PowerShell detection"
)

# Step 3: Determine kill chain stage
kill_chain = analyze_kill_chain_stage(
    iocs=analysis.get("extracted_iocs", []),
    include_hunting_suggestions=True
)

# Step 4: Create investigation
create_investigation(
    name="PowerShell Alert Investigation",
    description=f"Investigating {analysis.get('total_hits')} suspicious events",
    severity=analysis.get("severity", "medium")
)
```

### Severity Classification

| Level | Criteria | Response Time |
|-------|----------|---------------|
| Critical | Active breach, ransomware, data exfiltration | Immediate |
| High | Confirmed malware, credential theft | Within 4 hours |
| Medium | Suspicious activity, policy violation | Within 24 hours |
| Low | Minor anomaly, false positive likely | Within 72 hours |

## Phase 3: Containment, Eradication, Recovery

**Objective**: Limit impact, remove threat, restore operations.

### Containment Strategies

| Strategy | When to Use | CrowdSentinel Support |
|----------|-------------|----------------------|
| Short-term | Immediate threat | `export_iocs(format="values")` for blocking |
| Long-term | Extended investigation | `get_host_activity_timeline()` for scope |
| Evidence preservation | Legal/forensic needs | `get_investigation_summary()` |

### Scope Assessment

```python
# Identify all affected hosts
affected_hosts = set()

# Search for IoCs across environment
for ioc in investigation_iocs:
    results = hunt_for_ioc(
        index="winlogbeat-*",
        ioc=ioc["value"],
        ioc_type=ioc["type"],
        timeframe_minutes=10080  # 7 days
    )
    for hit in results.get("hits", []):
        affected_hosts.add(hit.get("host", {}).get("name"))

print(f"Affected hosts: {len(affected_hosts)}")
```

### Eradication Checklist

- [ ] Identify all compromised accounts
- [ ] Identify all compromised hosts
- [ ] Document persistence mechanisms
- [ ] Remove malware/backdoors
- [ ] Reset compromised credentials
- [ ] Patch exploited vulnerabilities

## Phase 4: Post-Incident Activity

**Objective**: Learn and improve from the incident.

### Documentation Requirements

```python
# Generate final report
report = generate_investigation_report(
    analysis_results=[analysis1, analysis2, ...],
    investigation_context="Complete incident summary"
)

# Close investigation
close_investigation(
    resolution="Contained ransomware to 3 hosts. Full remediation complete."
)
```

### Lessons Learned Questions

1. How was the incident detected?
2. What was the initial attack vector?
3. How long was the dwell time?
4. What data/systems were compromised?
5. How effective was our response?
6. What detection improvements are needed?
7. What preventive measures should be implemented?

## Incident Categories

| Category | Examples | Primary Kill Chain Stages |
|----------|----------|--------------------------|
| Malware | Ransomware, trojans, worms | Installation, Actions |
| Phishing | Credential theft, BEC | Delivery, Exploitation |
| Insider Threat | Data theft, sabotage | Collection, Exfiltration |
| Web Attack | SQLi, XSS, RCE | Delivery, Exploitation |
| DoS/DDoS | Service disruption | Impact |
| Unauthorised Access | Brute force, credential stuffing | Initial Access |

## CrowdSentinel IR Toolkit Summary

| Phase | Primary Tools | Secondary Tools |
|-------|--------------|-----------------|
| Preparation | `discover_all_assets`, `get_cluster_health` | `get_rule_statistics` |
| Detection | `execute_detection_rule`, `threat_hunt_search` | `smart_search`, `quick_count` |
| Analysis | `analyze_search_results`, `analyze_kill_chain_stage` | `map_events_to_kill_chain` |
| Containment | `hunt_for_ioc`, `get_host_activity_timeline` | `export_iocs` |
| Recovery | `generate_investigation_report` | `close_investigation` |
| Lessons Learned | `get_investigation_summary` | `get_shared_iocs` |

## Resources

- NIST SP 800-61 Rev 2: https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final
- NIST Cybersecurity Framework: https://www.nist.gov/cyberframework
- CISA IR Guidelines: https://www.cisa.gov/incident-response
