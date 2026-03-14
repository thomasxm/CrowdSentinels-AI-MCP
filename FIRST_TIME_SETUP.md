# First Time Setup Guide

## For Users Who Just Downloaded This Repository

This guide will walk you through setting up the CrowdSentinel AI MCP Server from scratch.

## Prerequisites

Before running the setup script, you need:

### 1. Claude Code Installed

**Check if you have Claude Code:**
```bash
claude --version
```

**If not installed, install Claude Code:**

Visit: https://docs.anthropic.com/claude/docs/claude-cli

Or install via:
```bash
# Linux/Mac (recommended method will be shown on the official site)
curl -fsSL https://claude.com/install.sh | sh
```

**Verify installation:**
```bash
which claude
# Should output: /home/username/.local/bin/claude (or similar)
```

### 2. Python 3.10+

**Check Python version:**
```bash
python3 --version
```

**If not installed:**
- Ubuntu/Debian: `sudo apt install python3`
- macOS: `brew install python3`
- Other: See https://www.python.org/downloads/

### 3. Elasticsearch Access

You need either:
- **Option A**: A running Elasticsearch cluster (local or remote)
- **Option B**: Docker installed to run Elasticsearch locally

**To run Elasticsearch locally with Docker:**
```bash
# Check if Docker is installed
docker --version

# If not, install Docker first:
# Ubuntu: sudo apt install docker.io
# macOS: brew install --cask docker
# Or visit: https://docs.docker.com/get-docker/

# Start Elasticsearch using the provided docker-compose:
cd /path/to/crowdsentinel-mcp-server
docker-compose -f docker-compose-elasticsearch.yml up -d

# Wait 30 seconds, then verify:
curl -k -u elastic:changeme https://localhost:9200
```

---

## Quick Setup (Automated)

### Step 1: Clone/Download This Repository

```bash
cd /path/where/you/want/the/server
# Repository already downloaded if you're reading this!
```

### Step 2: Make Setup Script Executable

```bash
chmod +x setup.sh
```

### Step 3: Run Setup Script

```bash
./setup.sh
```

**The script will automatically:**

1. ✅ Check for prerequisites (pipx, uv, Claude CLI)
2. ✅ Auto-install missing prerequisites (pipx, uv)
3. ✅ Install all Python dependencies
4. ✅ Prompt you for Elasticsearch credentials (NEVER hardcoded!)
5. ✅ Test connection to Elasticsearch
6. ✅ Configure Claude Code with the MCP server
7. ✅ Enable automatic response size limiting

**What it WON'T do (you must do manually):**
- ❌ Install Claude Code (must be done separately)
- ❌ Install Docker (must be done separately if you want local Elasticsearch)

---

## What Happens During Setup

### 1. Prerequisite Check

```
✓ Python 3 found: Python 3.10.12
✓ pipx found: 1.2.0
✓ uv found: 0.1.0
✓ Claude CLI found
✓ curl found
```

If any are missing:
- **pipx** → Script installs automatically
- **uv** → Script installs automatically via pipx
- **Claude CLI** → Script STOPS and tells you to install it first
- **curl** → Script STOPS and tells you to install it

### 2. Dependency Installation

```
Installing Python packages with uv...
✓ All dependencies installed (49 packages)
```

Creates a virtual environment at `.venv/` with all required packages.

### 3. Elasticsearch Configuration

**Interactive prompts:**
```
Elasticsearch Host (e.g., http://localhost:9200): http://localhost:9200

Authentication Method:
  1) Username & Password
  2) API Key
Select authentication method (1 or 2): 1

Elasticsearch Username (default: elastic): elastic
Elasticsearch Password: [hidden input]

Verify SSL certificates? (y/n, recommended: y for production): n
Enable read-only mode (disable write operations)? (y/n, recommended: y for security): y
Request timeout in seconds (press Enter to skip):
```

**What gets configured:**
- ✅ Connection details (host, auth)
- ✅ Security settings (SSL, read-only mode)
- ✅ Timeout settings (optional)
- ✅ **NO HARDCODED SECRETS** - all entered interactively

### 4. Connection Validation

```
Testing connection to http://localhost:9200...
✓ Connection successful!
  Cluster: docker-cluster
  Elasticsearch Version: 8.17.2
```

If connection fails, you can choose to:
- Fix the connection and try again
- Continue anyway (for offline setup)

### 5. MCP Server Configuration

```
Adding MCP server to Claude Code...
Enabling automatic response size limiting (max 8,000 tokens)
✓ MCP server configured successfully!
✓ Response size limiting enabled - prevents context overflow
```

**What this does:**
- Updates `~/.claude.json` with server configuration
- Registers the MCP server with Claude Code
- Sets environment variables for Elasticsearch connection
- Enables automatic response limiting

**Configuration location:** `~/.claude.json`

**Configuration added:**
```json
{
  "mcpServers": {
    "crowdsentinel": {
      "type": "stdio",
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/crowdsentinel-mcp-server",
        "run",
        "crowdsentinel-mcp-server"
      ],
      "env": {
        "ELASTICSEARCH_HOSTS": "http://localhost:9200",
        "ELASTICSEARCH_USERNAME": "elastic",
        "ELASTICSEARCH_PASSWORD": "your-password",
        "VERIFY_CERTS": "false",
        "DISABLE_HIGH_RISK_OPERATIONS": "true"
      }
    }
  }
}
```

---

## After Setup: Using the MCP Server

### Start Claude Code

```bash
claude
```

### Load the MCP Server

```
> /mcp
```

You should see:
```
Available MCP servers:
  - crowdsentinel (this one!)
  - [any other servers you have]
```

Select `crowdsentinel` by clicking or typing it.

### Test It Works

```
> Discover all assets in my Elasticsearch cluster
```

Expected response:
```
✓ Connected to Elasticsearch
✓ Scanning indices...
✓ Found 1 index: winlogbeat-*
✓ Asset discovery complete!

Total indices: 1
Total documents: 70,188
...
```

---

## Troubleshooting

### Issue: "Claude CLI not found"

**Solution:**
Install Claude Code first:
```bash
curl -fsSL https://claude.com/install.sh | sh
source ~/.bashrc  # or restart terminal
claude --version
```

### Issue: "Connection refused" during validation

**Solution:**
Elasticsearch isn't running. Start it:
```bash
# If using Docker:
docker-compose -f docker-compose-elasticsearch.yml up -d

# Wait 30 seconds
sleep 30

# Verify:
curl -k -u elastic:changeme https://localhost:9200
```

### Issue: "MCP server not showing in /mcp list"

**Solution:**
1. Check if configuration was added:
   ```bash
   cat ~/.claude.json | grep crowdsentinel
   ```

2. If missing, re-run setup:
   ```bash
   ./setup.sh
   ```

3. Restart Claude Code:
   ```bash
   # Exit current session
   exit

   # Start new session
   claude
   ```

### Issue: "Authentication failed"

**Solution:**
Your Elasticsearch credentials are wrong. Update them:
```bash
# Re-run setup to reconfigure
./setup.sh

# Or manually edit ~/.claude.json
nano ~/.claude.json
# Find "crowdsentinel" section
# Update ELASTICSEARCH_USERNAME and ELASTICSEARCH_PASSWORD
```

### Issue: Setup script fails with permission error

**Solution:**
```bash
chmod +x setup.sh
./setup.sh
```

---

## Manual Configuration (Advanced)

If you prefer not to use the setup script:

### 1. Install Dependencies Manually

```bash
# Install uv
pip install uv

# Install project dependencies
uv sync
```

### 2. Configure Claude Code Manually

```bash
claude mcp add crowdsentinel \
  --env ELASTICSEARCH_HOSTS="http://localhost:9200" \
  --env ELASTICSEARCH_USERNAME="elastic" \
  --env ELASTICSEARCH_PASSWORD="your-password" \
  --env VERIFY_CERTS="false" \
  --env DISABLE_HIGH_RISK_OPERATIONS="true" \
  -- uv --directory /path/to/crowdsentinel-mcp-server run crowdsentinel-mcp-server
```

---

## What You Get

After successful setup:

### Tools Available (36 total):
- **Asset Discovery** (4 tools) - Scan and catalogue indices
- **EQL Queries** (3 tools) - Event Query Language
- **Threat Hunting** (6 tools) - Automated attack detection
- **IoC Analysis** (2 tools) - Indicator analysis
- **Standard Elasticsearch** (18 tools) - CRUD operations
- **Plus 3 more** advanced analysis tools

### Features Enabled:
- ✅ Automatic response size limiting (8,000 token max)
- ✅ Intelligent summarization (chunks large results)
- ✅ MITRE ATT&CK mapping
- ✅ Pyramid of Pain IoC prioritisation
- ✅ 8 pre-built attack patterns
- ✅ Read-only mode (safe for production)

---

## Switching Transport Modes

After initial setup, you can safely switch between stdio, SSE, and Streamable HTTP modes using the provided script:

```bash
./switch-transport.sh
```

**What the script does:**
1. Shows your current transport configuration
2. Prompts you to select a new transport mode
3. Safely stops any running background server
4. Updates Claude Code configuration
5. Starts new server (for HTTP/SSE modes)
6. Saves new configuration

**When to switch:**
- **stdio → HTTP/SSE**: When you want external API access or web integration
- **HTTP/SSE → stdio**: When you want simpler Claude Code-only usage
- **SSE ↔ HTTP**: When you prefer different HTTP transport protocol

**Example usage:**
```bash
chmod +x switch-transport.sh
./switch-transport.sh

# Follow the interactive prompts to:
# 1. Choose new transport mode (stdio/SSE/HTTP)
# 2. Configure port (for HTTP/SSE)
# 3. Confirm the switch
```

---

## Next Steps

1. **Read the guides:**
   - [QUICK_START.md](QUICK_START.md) - 5-minute quick start
   - [THREAT_HUNTING_GUIDE.md](THREAT_HUNTING_GUIDE.md) - Complete hunting guide
   - [HOW_TO_USE.md](HOW_TO_USE.md) - Usage examples

2. **Try example queries:**
   - "Check for brute force attempts in the last hour"
   - "Find suspicious PowerShell commands"
   - "Hunt for lateral movement indicators"

3. **Explore documentation:**
   - [ARCHITECTURE.md](ARCHITECTURE.md) - Technical reference
   - [RESPONSE_SIZE_LIMITING.md](RESPONSE_SIZE_LIMITING.md) - Size limiting guide

---

## Support

- **Documentation**: See README.md
- **Issues**: GitHub Issues
- **Questions**: Check existing documentation first

---

**You're ready to hunt threats! 🔍🚀**
