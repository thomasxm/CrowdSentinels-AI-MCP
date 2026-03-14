# Pyramid of Pain Reference

## Overview

The Pyramid of Pain, created by David Bianco, illustrates the difficulty attackers face when defenders detect and respond to different types of indicators. Higher levels cause more "pain" to attackers.

## The Pyramid

```
                        ┌───────────┐
                        │   TTPs    │  ← TOUGH (Behaviours)
                       ┌┴───────────┴┐
                       │    Tools    │  ← CHALLENGING
                      ┌┴─────────────┴┐
                      │   Artifacts   │  ← ANNOYING
                     ┌┴───────────────┴┐
                     │    Domains      │  ← SIMPLE
                    ┌┴─────────────────┴┐
                    │   IP Addresses    │  ← EASY
                   ┌┴───────────────────┴┐
                   │    Hash Values      │  ← TRIVIAL
                   └─────────────────────┘
```

## Levels Explained

### Level 1: Hash Values (Trivial)

**What**: File hashes (MD5, SHA1, SHA256)

**Pain Level**: Trivial - Attackers change a single byte and hash changes

**CrowdSentinel Hunting**:
```python
hunt_for_ioc(
    index="winlogbeat-*",
    ioc="a1b2c3d4e5f6...",
    ioc_type="hash"
)
```

**Limitations**:
- Single modification defeats detection
- Polymorphic malware bypasses easily
- Only useful for known-bad files

### Level 2: IP Addresses (Easy)

**What**: Source/destination IP addresses

**Pain Level**: Easy - Attackers use VPNs, proxies, compromised hosts

**CrowdSentinel Hunting**:
```python
hunt_for_ioc(
    index="winlogbeat-*",
    ioc="203.0.113.42",
    ioc_type="ip"
)
```

**Considerations**:
- Cloud IPs may be shared/recycled
- Dynamic infrastructure (bulletproof hosting)
- False positives from CDNs, shared hosting

### Level 3: Domain Names (Simple)

**What**: C2 domains, phishing domains

**Pain Level**: Simple - Domain registration is cheap and fast

**CrowdSentinel Hunting**:
```python
hunt_for_ioc(
    index="winlogbeat-*",
    ioc="malicious-c2.evil",
    ioc_type="domain"
)
```

**Techniques**:
- DGA (Domain Generation Algorithms)
- Fast-flux DNS
- Compromised legitimate domains

### Level 4: Network/Host Artifacts (Annoying)

**What**: Registry keys, mutex names, file paths, user-agents

**Pain Level**: Annoying - Requires code changes to modify

**CrowdSentinel Hunting**:
```python
# Registry persistence
search_with_lucene(
    index="winlogbeat-*",
    lucene_query='registry.path:*\\CurrentVersion\\Run\\*'
)

# Specific user-agent
search_with_lucene(
    index="packetbeat-*",
    lucene_query='user_agent.original:"Mozilla/4.0 (compatible)"'
)
```

**Examples**:
- Specific registry keys for persistence
- Known malware mutex names
- Characteristic file paths
- Distinctive HTTP headers

### Level 5: Tools (Challenging)

**What**: Specific attack tools (Mimikatz, Cobalt Strike, etc.)

**Pain Level**: Challenging - Requires developing/acquiring new tools

**CrowdSentinel Hunting**:
```python
# Hunt for known tools
hunt_for_ioc(
    index="winlogbeat-*",
    ioc="mimikatz",
    ioc_type="process"
)

# Tool-specific detection rules
rules = list_detection_rules(search_term="mimikatz")
for rule in rules["rules"]:
    execute_detection_rule(rule_id=rule["id"], index="winlogbeat-*")
```

**Detection Strategies**:
- Process names and command lines
- YARA rules for tool signatures
- Behavioural patterns unique to tools

### Level 6: TTPs (Tough)

**What**: Tactics, Techniques, and Procedures - how attackers operate

**Pain Level**: Tough - Requires changing attacker methodology

**CrowdSentinel Hunting**:
```python
# Hunt by kill chain stage (behavioural)
hunt_by_kill_chain_stage(
    index="winlogbeat-*",
    stage="CREDENTIAL_ACCESS",
    timeframe_minutes=1440
)

# TTP-based detection rules
rules = search_rules_by_mitre_attack(
    tactic="credential_access",
    platform="windows"
)
```

**Examples**:
- LSASS access patterns (T1003.001)
- Scheduled task creation for persistence (T1053.005)
- Process injection techniques (T1055)

## Hunting Strategy by Level

| Level | Priority | Hunting Approach | Token Efficiency |
|-------|----------|------------------|------------------|
| Hash | 6 (Lowest) | Quick IoC check | High (fast) |
| IP | 5 | Network correlation | High |
| Domain | 4 | DNS analysis | Medium |
| Artifact | 3 | Registry/file monitoring | Medium |
| Tool | 2 | Process/command analysis | Low |
| TTP | 1 (Highest) | Behavioural detection | Low (thorough) |

## CrowdSentinel Priority Mapping

The `analyze_kill_chain_stage` tool uses Pyramid of Pain priorities:

```python
analysis = analyze_kill_chain_stage(
    iocs=[
        {"type": "hash", "value": "abc123..."},      # Priority 1 (trivial)
        {"type": "ip", "value": "192.168.1.100"},    # Priority 2 (easy)
        {"type": "domain", "value": "evil.com"},     # Priority 3 (simple)
        {"type": "process", "value": "mimikatz.exe"} # Priority 5 (challenging)
    ]
)
# Returns IoCs sorted by priority (higher = more valuable to focus on)
```

## Practical Application

### Investigation Workflow

```
START with whatever IoC you have
    │
    ├─→ If Hash/IP/Domain found
    │       └─→ Use these to find HIGHER LEVEL indicators
    │           └─→ What tool created this file?
    │           └─→ What behaviour triggered this connection?
    │
    └─→ If TTP/Tool identified
            └─→ More valuable for PROACTIVE hunting
            └─→ Harder for attacker to evade
```

### Example: Escalating from IP to TTP

```python
# Step 1: Found suspicious IP in logs
ip_results = hunt_for_ioc(index="winlogbeat-*", ioc="203.0.113.42", ioc_type="ip")

# Step 2: Identify what process made the connection
# Look at process.name, process.command_line in results

# Step 3: Determine the TTP
analysis = analyze_search_results(
    search_results=ip_results,
    context="Suspicious outbound connection"
)
# Returns MITRE techniques (TTPs)

# Step 4: Hunt for TTP across environment
for technique in analysis.get("mitre_techniques", []):
    # Now hunting at TTP level - much more valuable
    hunt_by_kill_chain_stage(
        index="winlogbeat-*",
        stage=technique_to_stage_mapping[technique]
    )
```

## Key Takeaways

1. **Start Low, Go High**: Begin with any indicator, but always try to identify higher-level patterns
2. **Invest in TTP Detection**: Rules that detect behaviours are more durable than IoC lists
3. **Automation**: Automate low-level IoC blocking, invest analyst time in TTP hunting
4. **Context is King**: A hash alone is trivial; a hash with its TTP context is valuable

## Resources

- Original Blog Post: https://detect-respond.blogspot.com/2013/03/the-pyramid-of-pain.html
- David Bianco's Research: https://twitter.com/DavidJBianco
