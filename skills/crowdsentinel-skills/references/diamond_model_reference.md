# Diamond Model of Intrusion Analysis Reference

## Overview

The Diamond Model provides a framework for intrusion analysis by examining the relationships between four core features of any intrusion activity: Adversary, Capability, Infrastructure, and Victim.

## The Diamond

```
                         ADVERSARY
                            │
                            │ Who is attacking?
                            │
              ┌─────────────┼─────────────┐
              │             │             │
              │             │             │
         CAPABILITY ────────┼──────── INFRASTRUCTURE
              │             │             │
         What tools?        │        What IPs/Domains?
              │             │             │
              └─────────────┼─────────────┘
                            │
                            │ Who is targeted?
                            │
                         VICTIM
```

## Core Features

### 1. Adversary

**Definition**: The threat actor conducting the intrusion.

**Sub-features**:
- Adversary Operator: Person conducting the attack
- Adversary Customer: Person/org benefiting from attack

**CrowdSentinel Analysis**:
```python
# Identify adversary through TTPs
analysis = analyze_kill_chain_stage(
    iocs=discovered_iocs,
    include_hunting_suggestions=True
)
# TTPs often indicate adversary groups
```

**Questions to Answer**:
- Who is behind this attack?
- What is their motivation (financial, espionage, hacktivism)?
- What threat group/APT does this match?

### 2. Capability

**Definition**: The tools and techniques used in the attack.

**Sub-features**:
- Capability Capacity: What the capability can do
- Adversary Arsenal: Collection of capabilities

**CrowdSentinel Analysis**:
```python
# Identify tools used
hunt_for_ioc(index="winlogbeat-*", ioc="mimikatz", ioc_type="process")
hunt_for_ioc(index="winlogbeat-*", ioc="cobalt strike", ioc_type="process")

# Identify techniques
analysis = analyze_search_results(
    search_results=results,
    context="Tool and technique identification"
)
# Returns: MITRE techniques (capabilities)
```

**Questions to Answer**:
- What malware/tools are being used?
- What exploits are leveraged?
- What techniques are employed?
- Is this commodity malware or custom?

### 3. Infrastructure

**Definition**: Physical and logical communication structures used.

**Types**:
- Type I: Adversary-owned
- Type II: Compromised/third-party

**CrowdSentinel Analysis**:
```python
# Network infrastructure
hunt_for_ioc(index="winlogbeat-*", ioc="203.0.113.42", ioc_type="ip")
hunt_for_ioc(index="winlogbeat-*", ioc="malicious.com", ioc_type="domain")

# C2 infrastructure detection
hunt_by_kill_chain_stage(
    index="winlogbeat-*",
    stage="COMMAND_AND_CONTROL"
)
```

**Questions to Answer**:
- What IPs/domains are used for C2?
- Is infrastructure owned or compromised?
- What hosting providers are used?
- Is there overlap with known threat actor infrastructure?

### 4. Victim

**Definition**: The target of the intrusion.

**Sub-features**:
- Victim Persona: Targeted organisation/person type
- Victim Assets: Specific systems/data targeted

**CrowdSentinel Analysis**:
```python
# Identify affected hosts
get_host_activity_timeline(
    index="winlogbeat-*",
    hostname="DESKTOP-ABC123",
    start_time="now-7d"
)

# Scope impact
investigation_summary = get_investigation_summary()
# Returns: affected hosts and users
```

**Questions to Answer**:
- Who/what was targeted?
- What systems were compromised?
- What data was accessed/stolen?
- Why was this victim targeted?

## Meta-Features

### Timestamp

**Definition**: When the event occurred.

```python
# Timeline analysis
get_host_activity_timeline(
    index="winlogbeat-*",
    hostname="victim-host",
    start_time="2024-01-01T00:00:00",
    end_time="2024-01-02T00:00:00"
)
```

### Phase

**Definition**: Kill chain phase of the activity.

```python
# Map to kill chain
map_events_to_kill_chain(events=search_results.get("hits", []))
```

### Result

**Definition**: Outcome of the adversary's action.

- Success: Adversary achieved objective
- Failure: Adversary did not achieve objective
- Unknown: Outcome undetermined

### Direction

**Definition**: Direction of the attack.

- Adversary → Infrastructure → Victim
- Victim → Infrastructure → Adversary (C2 callback)
- Infrastructure → Infrastructure (lateral movement)
- Adversary → Victim (direct attack)

### Methodology

**Definition**: General category of activity.

Examples: Phishing, drive-by, insider threat, supply chain

### Resources

**Definition**: Elements required for the event.

- Software (malware, tools)
- Knowledge (exploits, techniques)
- Information (recon data)
- Hardware (infrastructure)
- Funds (registration, hosting)
- Access (accounts, network)

## Pivot Analysis

The Diamond Model excels at pivot analysis - using one feature to discover others.

### Pivot Examples

```
CAPABILITY → INFRASTRUCTURE
    │
    └─→ "What C2 infrastructure does this malware use?"
        hunt_for_ioc(ioc="malware.exe", ioc_type="process")
        → Find network connections in results
        → Identify C2 IPs/domains

INFRASTRUCTURE → VICTIM
    │
    └─→ "What other systems connected to this C2?"
        hunt_for_ioc(ioc="c2-domain.com", ioc_type="domain")
        → Find all hosts that connected
        → Expand victim list

CAPABILITY → ADVERSARY
    │
    └─→ "What threat group uses this malware?"
        analyze_kill_chain_stage(iocs=[...])
        → MITRE techniques often map to threat groups
        → Cross-reference with threat intelligence
```

### CrowdSentinel Pivot Workflow

```python
# Start with single IoC (e.g., suspicious IP)
initial_results = hunt_for_ioc(
    index="winlogbeat-*",
    ioc="203.0.113.42",
    ioc_type="ip"
)

# Analyse to extract related IoCs
analysis = analyze_search_results(
    search_results=initial_results,
    context="Diamond Model pivot analysis"
)

# Pivot to related indicators
for ioc in analysis.get("extracted_iocs", []):
    # Infrastructure pivot
    if ioc["type"] in ["ip", "domain"]:
        hunt_for_ioc(index="*", ioc=ioc["value"], ioc_type=ioc["type"])

    # Capability pivot
    if ioc["type"] in ["process", "hash"]:
        hunt_for_ioc(index="winlogbeat-*", ioc=ioc["value"], ioc_type=ioc["type"])

# Identify victims (hosts)
victims = set()
for hit in initial_results.get("hits", []):
    victims.add(hit.get("host", {}).get("name"))

# Build Diamond Model summary
diamond = {
    "adversary": analysis.get("mitre_techniques"),  # TTPs suggest adversary
    "capability": analysis.get("processes", []) + analysis.get("command_lines", []),
    "infrastructure": [i for i in analysis.get("extracted_iocs", []) if i["type"] in ["ip", "domain"]],
    "victim": list(victims)
}
```

## Activity Thread Analysis

Track related activities across time:

```python
# Create investigation to track activity thread
create_investigation(
    name="APT Activity Thread",
    description="Tracking related activities across Diamond Model features"
)

# Add discovered IoCs
add_iocs_to_investigation(iocs=all_discovered_iocs)

# Generate comprehensive report
report = generate_investigation_report(
    analysis_results=[analysis1, analysis2, analysis3],
    investigation_context="Diamond Model comprehensive analysis"
)
```

## Integration with Other Frameworks

| Diamond Feature | Kill Chain Stage | MITRE Tactic | Pyramid Level |
|-----------------|------------------|--------------|---------------|
| Adversary | All | All | TTPs |
| Capability | Delivery, Exploitation, Installation | Execution, Persistence | Tools |
| Infrastructure | Delivery, C2 | Initial Access, C2 | IP, Domain |
| Victim | Actions on Objectives | Collection, Exfiltration | - |

## Resources

- Original Paper: "The Diamond Model of Intrusion Analysis" (Caltagirone, Pendergast, Betz)
- ThreatConnect Implementation: https://threatconnect.com/blog/diamond-model-threat-intelligence/
- MITRE Mapping: https://attack.mitre.org/
