# Quick Start Guide - 5 Minutes to Threat Hunting

## 🚀 Setup (One-Time)

### With Docker Compose (Recommended)

```bash
# 1. Start Elasticsearch
cd /home/kali/Desktop/elastic_mcp_bundle/crowdsentinel-mcp-server
docker-compose -f docker-compose-elasticsearch.yml up -d

# 2. Wait 30 seconds for Elasticsearch to start

# 3. Verify Elasticsearch is running
curl -k -u elastic:changeme https://localhost:9200

# 4. Configuration is already done!
# MCP Config: ~/.config/claude-code/mcp_config.json ✅
# Environment: .env file ✅
```

### With Existing Elasticsearch

```bash
# 1. Edit environment file
cd /home/kali/Desktop/elastic_mcp_bundle/crowdsentinel-mcp-server
cp .env.example .env
nano .env  # Update with your credentials

# 2. Edit Claude Code config
nano ~/.config/claude-code/mcp_config.json
# Update ELASTICSEARCH_HOSTS, USERNAME, PASSWORD

# 3. That's it!
```

---

## 💬 Example Questions for Claude Code

### Basic Discovery

```
"Discover all assets in my Elasticsearch cluster"
"What indices do I have?"
"Show me all Windows event log indices"
```

### Threat Hunting

```
"Check for suspicious attacks in the last 15 minutes"
"Look for brute force attempts in the last hour"
"Find suspicious PowerShell commands in the last 24 hours"
"Hunt for lateral movement indicators"
```

### Host Investigation

```
"What processes are running on host WS001?"
"Show me the activity timeline for server DC01"
"Investigate all activity from user 'admin' in the last 24 hours"
```

### IoC Hunting

```
"Search for IP address 192.168.1.100 in all logs"
"Hunt for file named malicious.exe"
"Track user 'suspicious_account' across all systems"
```

### Specific Attack Patterns

```
"Detect failed login attempts (brute force)"
"Find privilege escalation attempts"
"Look for persistence mechanisms (scheduled tasks, services)"
"Identify credential access attempts"
```

### Compliance Checks

```
"Are we meeting PCI-DSS logging requirements?"
"Check if we're logging authentication events"
"Verify privileged access logging is working"
```

---

## 🎯 What Claude Code Will Do

When you ask a security question, Claude Code will:

1. **Clarify** - Ask if Windows or Linux (if needed)
2. **Discover** - Find relevant log indices automatically
3. **Hunt** - Execute targeted threat hunting queries
4. **Analyse** - Extract IoCs with Pyramid of Pain prioritisation
5. **Map** - Connect findings to MITRE ATT&CK framework
6. **Recommend** - Suggest specific follow-up investigations
7. **Report** - Generate comprehensive incident reports

---

## 🛠️ Available Tools (36 Total)

### Threat Hunting (18 new tools)

**Asset Discovery:**
- discover_all_assets
- get_saved_assets
- get_indices_by_type
- get_index_metadata

**EQL Queries:**
- eql_search
- eql_delete
- eql_get_status

**Threat Hunting:**
- hunt_by_timeframe
- analyze_failed_logins
- analyze_process_creation
- hunt_for_ioc
- get_host_activity_timeline
- search_with_lucene

**IoC Analysis:**
- analyze_search_results
- generate_investigation_report

### Original Tools (18 tools)

- list_indices, get_index, create_index, delete_index
- search_documents, index_document, get_document, delete_document, delete_by_query
- get_cluster_health, get_cluster_stats
- list_aliases, get_alias, put_alias, delete_alias
- create_data_stream, get_data_stream, delete_data_stream
- general_api_request

---

## 📊 Attack Patterns Detected

Claude Code can automatically detect:

1. **Brute Force** - Failed login attempts (Event ID 4625, 4776)
2. **Privilege Escalation** - Privilege abuse (Event ID 4672, 4673, 4674)
3. **Lateral Movement** - Moving between systems (Event ID 4624, 4648)
4. **Persistence** - Backdoors (Event ID 4697, 4698, 4720, 4732)
5. **Suspicious Processes** - LOLBins (Event ID 4688)
6. **Encoded Commands** - Obfuscated PowerShell (Event ID 4688)
7. **Credential Access** - Credential dumping (Event ID 4688, 4656)
8. **Port Scanning** - Network reconnaissance

---

## 🎓 Key Concepts

### Pyramid of Pain (IoC Prioritisation)

```
Priority 6 (TTPs) ← Focus here! Hard for attackers to change
Priority 5 (Tools)
Priority 4 (Network Artifacts)
Priority 3 (Domains)
Priority 2 (IPs)
Priority 1 (Hashes)
```

Claude Code automatically prioritises IoCs, focusing on high-value indicators.

### MITRE ATT&CK Mapping

Every finding is mapped to MITRE ATT&CK:
- Event ID 4625 → T1110 (Brute Force)
- Event ID 4688 → T1059 (Command/Scripting)
- Event ID 4698 → T1053.005 (Scheduled Task)

---

## 🔒 Security

- ✅ **Read-Only by Default** - Cannot modify or delete logs
- ✅ **High-Risk Operations Disabled** - No write operations
- ✅ **Audit Trail** - All queries are logged
- ✅ **Safe for Production** - Designed for security investigations

---

## 📖 Full Documentation

- **CLAUDE_CODE_SETUP.md** - Complete setup guide
- **THREAT_HUNTING_GUIDE.md** - How to use each tool
- **AI_AGENT_INTEGRATION.md** - How Claude Code behaves
- **ARCHITECTURE.md** - Technical reference
- **IMPLEMENTATION_SUMMARY.md** - What was implemented

---

## ❓ Troubleshooting

### Elasticsearch not connecting?

```bash
# Check if Elasticsearch is running
curl -k -u elastic:changeme https://localhost:9200

# If using Docker:
docker-compose -f docker-compose-elasticsearch.yml ps

# Start if stopped:
docker-compose -f docker-compose-elasticsearch.yml up -d
```

### Tools not showing up?

Check Claude Code configuration:
```bash
cat ~/.config/claude-code/mcp_config.json
```

### Authentication failed?

Verify credentials in `mcp_config.json` match your Elasticsearch setup.

---

## 🎉 You're Ready!

Ask Claude Code:

```
"Discover all assets in my Elasticsearch cluster"
```

And start hunting threats! 🔍
