# How to Use the Elasticsearch MCP Server with Claude Code

## ✅ Setup Complete!

The Elasticsearch Threat Hunting MCP server is now configured and ready to use!

---

## 🔄 How to Load the MCP Server

### Option 1: Using /mcp Command (Recommended)

1. **Type `/mcp` in  Code**

2. **You should see TWO servers:**
   - `hexstrike-ai` (your existing server)
   - `crowdsentinel` (the new server) ← This one!

3. **Click or select `crowdsentinel`** to activate it

4. **The server will start automatically!**

---

## 🚀 Quick Start (No Elasticsearch Running Yet)

### Step 1: Start Elasticsearch with Docker

```bash
cd /home/kali/Desktop/elastic_mcp_bundle/crowdsentinel-mcp-server

# Start Elasticsearch
docker-compose -f docker-compose-elasticsearch.yml up -d

# Wait 30 seconds for it to start

# Verify it's running:
curl -k -u elastic:changeme https://localhost:9200
```

You should see JSON output with Elasticsearch version info.

### Step 2: Load the MCP Server in Claude Code

1. Type `/mcp`
2. Select `crowdsentinel`
3. Server starts automatically!

### Step 3: Try Your First Query

Type in Claude Code:

```
Discover all assets in my Elasticsearch cluster
```

The server will:
- Connect to Elasticsearch
- Scan all indices
- Extract metadata (OS types, log sources, fields)
- Save to `assets/discovered_assets.json`
- Return the results!

---

## 📊 Example Questions to Ask

### Asset Discovery
```
"Discover all assets"
"Show me all Windows event log indices"
"Get metadata for winlogbeat indices"
```

### Threat Hunting
```
"Check for suspicious attacks in the last 15 minutes"
"Look for brute force attempts in the last hour"
"Find suspicious PowerShell commands"
"Hunt for lateral movement indicators"
```

### Host Investigation
```
"What processes are running on host WS001?"
"Show me the activity timeline for DC01 server"
"Investigate all activity from user 'admin'"
```

### IoC Hunting
```
"Search for IP address 192.168.1.100"
"Hunt for file named malicious.exe"
"Track user account 'suspicious_user'"
```

---

## 🛠️ Configuration Location

The MCP configuration is stored at:
```
/home/kali/.config/Code/User/mcp.json
```

Current configuration:
- **Elasticsearch Host**: https://localhost:9200
- **Username**: elastic
- **Password**: changeme
- **SSL Verification**: Disabled (for testing)
- **Write Operations**: Disabled (read-only mode)

### To Change Elasticsearch Credentials:

Edit `/home/kali/.config/Code/User/mcp.json` and update the `env` section:

```json
"env": {
  "ELASTICSEARCH_HOSTS": "https://your-host:9200",
  "ELASTICSEARCH_USERNAME": "your-username",
  "ELASTICSEARCH_PASSWORD": "your-password",
  "VERIFY_CERTS": "false",
  "DISABLE_HIGH_RISK_OPERATIONS": "true"
}
```

Then restart Claude Code or reload the MCP server.

---

## 🔍 Available Tools (40+ Total)

When you activate the server, you get access to:

### Detection Rule Tools (NEW!)
1. **list_detection_rules** - Browse 5000+ detection rules with filtering
2. **get_rule_details** - Get full rule query and metadata
3. **execute_detection_rule** - Run a specific rule against your data
4. **execute_multiple_rules** - Batch execute multiple rules
5. **search_rules_by_mitre_attack** - Find rules by MITRE ATT&CK tactic
6. **get_rule_statistics** - View rule library statistics
7. **hunt_with_rule_category** - Execute all rules in a category
8. **validate_rule_for_data** - Check if a rule works with your data ⭐
9. **suggest_rules_for_data** - Get rule recommendations based on your data ⭐

### Threat Hunting Tools
1. **discover_all_assets** - Scan and catalogue all indices
2. **get_saved_assets** - Load cached asset information
3. **get_indices_by_type** - Find indices by OS/log type
4. **get_index_metadata** - Get detailed index info
5. **eql_search** - Execute Event Query Language queries
6. **eql_delete** - Delete async EQL searches
7. **eql_get_status** - Get EQL search status
8. **hunt_by_timeframe** - Multi-pattern threat hunting
9. **analyze_failed_logins** - Detect brute force
10. **analyze_process_creation** - Find suspicious processes
11. **hunt_for_ioc** - Track specific IoCs
12. **get_host_activity_timeline** - Forensic timeline
13. **search_with_lucene** - Custom Lucene queries
14. **analyze_search_results** - Intelligent IoC analysis
15. **generate_investigation_report** - Create IR reports

### Original Elasticsearch Tools (18)
All the standard Elasticsearch operations (list_indices, search_documents, cluster health, etc.)

---

## 🎯 Using Detection Rules

### Example: Find and Execute Detection Rules

```
# List all Mimikatz detection rules
list_detection_rules(search_term="mimikatz")

# Get details of a specific rule
get_rule_details(rule_id="windows_powershell_posh_ps_potential_invoke_mimikatz_eql")

# Check if a rule is compatible with your data first!
validate_rule_for_data(rule_id="...", index="winlogbeat-*")

# Execute the rule (use timeframe_minutes=0 for historical data)
execute_detection_rule(rule_id="...", index="winlogbeat-*", timeframe_minutes=0)
```

### Example: Get Rule Recommendations for Your Data

```
# Let the system suggest rules based on your data
suggest_rules_for_data(index="winlogbeat-*")
```

This will analyse your data and recommend detection rules that are likely to work with your log sources.

---

## 🎯 Attack Patterns Detected

The server can automatically hunt for:

1. **Brute Force** - Failed login attempts
2. **Privilege Escalation** - Privilege abuse
3. **Lateral Movement** - Moving between systems
4. **Persistence** - Backdoors and scheduled tasks
5. **Suspicious Processes** - LOLBins (Living off the Land)
6. **Encoded Commands** - Obfuscated PowerShell
7. **Credential Access** - Credential dumping (Mimikatz, etc.)
8. **Port Scanning** - Network reconnaissance

---

## 🔒 Security Features

- ✅ **Read-Only by Default** - Cannot modify logs
- ✅ **Write Operations Disabled** - Prevents accidental changes
- ✅ **Pyramid of Pain Prioritisation** - Focus on low-hanging fruits IoCs
- ✅ **MITRE ATT&CK Mapping** - Automatic technique identification
- ✅ **Audit Trail** - All queries are logged

---

## ❓ Troubleshooting

### Issue: "Connection refused" error

**Solution:**
```bash
# Check if Elasticsearch is running
curl -k -u elastic:changeme https://localhost:9200

# If not running, start it:
docker-compose -f docker-compose-elasticsearch.yml up -d

# Wait 30 seconds and try again
```

### Issue: Server doesn't appear in /mcp list

**Solution:**
1. Check configuration exists: `cat ~/.config/Code/User/mcp.json`
2. Verify the file has both `hexstrike-ai` and `crowdsentinel`
3. Restart Claude Code

### Issue: "Authentication failed"

**Solution:**
The default credentials are:
- Username: `elastic`
- Password: `changeme`

If using different credentials, update `/home/kali/.config/Code/User/mcp.json`

### Issue: No data in Elasticsearch

**Solution:**
The Docker Compose setup creates an empty Elasticsearch cluster. To add sample data:

1. Open Kibana: http://localhost:5601
2. Go to "Add data"
3. Load sample data (optional)

Or ingest real logs using Beats (Winlogbeat, Filebeat, etc.)

---

## 📚 Full Documentation

- **QUICK_START.md** - 5-minute quick start
- **THREAT_HUNTING_GUIDE.md** - Complete hunting guide
- **AI_AGENT_INTEGRATION.md** - How Claude Code behaves
- **ARCHITECTURE.md** - Technical reference
- **CLAUDE_CODE_SETUP.md** - Detailed setup guide

---

## 🎉 You're Ready!

1. Type `/mcp` in Claude Code
2. Select `crowdsentinel`
3. Ask: **"Discover all assets in my Elasticsearch cluster"**

Start hunting threats! 🔍🚀
