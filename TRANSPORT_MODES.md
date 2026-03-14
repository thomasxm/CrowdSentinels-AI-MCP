# MCP Transport Modes Guide

## Overview

The Elasticsearch Threat Hunting MCP Server supports three transport modes for communication between Claude Code and the MCP server. This guide explains each mode and how to switch between them.

---

## Transport Modes

### 1. stdio (Standard Input/Output)

**Recommended for:** Claude Code CLI users

**How it works:**
- Server communicates via standard input/output streams
- Claude Code automatically starts the server when needed
- Server stops when Claude Code session ends
- No network ports required
- No background processes

**Advantages:**
- ✅ Simplest setup
- ✅ Most secure (no network exposure)
- ✅ Automatic lifecycle management
- ✅ No port conflicts
- ✅ Works offline

**Disadvantages:**
- ❌ Only accessible from Claude Code
- ❌ Cannot be accessed via HTTP/curl
- ❌ Single concurrent connection

**Best for:**
- Local threat hunting with Claude Code
- Development and testing
- Maximum security requirements
- Single-user scenarios

**Configuration:**
```json
{
  "command": "uv",
  "args": [
    "--directory",
    "/path/to/crowdsentinel-mcp-server",
    "run",
    "crowdsentinel-mcp-server"
  ]
}
```

---

### 2. SSE (Server-Sent Events)

**Recommended for:** Web integrations and event streaming

**How it works:**
- Server runs as a persistent background service
- Exposes HTTP endpoint with event streaming
- Uses Server-Sent Events (SSE) protocol
- Supports long-lived connections
- Accessible via HTTP GET requests

**Advantages:**
- ✅ Real-time event streaming
- ✅ Accessible via web browsers
- ✅ Standard HTTP protocol
- ✅ Multiple concurrent connections
- ✅ Compatible with web frameworks

**Disadvantages:**
- ❌ Requires background process management
- ❌ Network port exposure
- ❌ Manual server lifecycle
- ❌ Potential port conflicts

**Best for:**
- Web-based threat hunting dashboards
- Integration with web applications
- Real-time event monitoring
- Multiple concurrent users

**Configuration:**
```json
{
  "command": "uv",
  "args": [
    "--directory",
    "/path/to/crowdsentinel-mcp-server",
    "run",
    "crowdsentinel-mcp-server",
    "--transport",
    "sse",
    "--port",
    "8001"
  ]
}
```

**Endpoint:** `http://localhost:8001/sse`

**Test with curl:**
```bash
curl http://localhost:8001/sse
```

---

### 3. Streamable HTTP

**Recommended for:** RESTful API integrations

**How it works:**
- Server runs as a persistent background service
- Exposes standard HTTP POST endpoint
- RESTful API interface
- Request/response model
- Accessible via any HTTP client

**Advantages:**
- ✅ Standard REST API
- ✅ Easy integration with any HTTP client
- ✅ Well-documented HTTP protocol
- ✅ Multiple concurrent connections
- ✅ Compatible with automation tools

**Disadvantages:**
- ❌ Requires background process management
- ❌ Network port exposure
- ❌ Manual server lifecycle
- ❌ Potential port conflicts

**Best for:**
- API integrations
- Automation scripts
- CI/CD pipelines
- Third-party tool integration
- Multiple concurrent users

**Configuration:**
```json
{
  "command": "uv",
  "args": [
    "--directory",
    "/path/to/crowdsentinel-mcp-server",
    "run",
    "crowdsentinel-mcp-server",
    "--transport",
    "streamable-http",
    "--port",
    "8001"
  ]
}
```

**Endpoint:** `http://localhost:8001/mcp`

**Test with curl:**
```bash
curl -X POST http://localhost:8001/mcp
```

---

## Comparison Table

| Feature | stdio | SSE | Streamable HTTP |
|---------|-------|-----|-----------------|
| **Ease of Setup** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| **Security** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐ |
| **Claude Code Integration** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐⭐ |
| **Web Access** | ❌ | ✅ | ✅ |
| **API Integration** | ❌ | ⭐⭐⭐ | ⭐⭐⭐⭐⭐ |
| **Real-time Streaming** | ❌ | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ |
| **Concurrent Users** | Single | Multiple | Multiple |
| **Background Service** | No | Yes | Yes |
| **Port Required** | No | Yes | Yes |
| **Auto-start** | Yes | Manual | Manual |

---

## Switching Transport Modes

### Using the Switch Script

The easiest way to switch between transport modes is using the provided script:

```bash
./switch-transport.sh
```

**What the script does:**
1. Shows your current transport configuration
2. Prompts you to select a new transport mode
3. Safely stops any running background server
4. Updates Claude Code configuration (`~/.claude.json`)
5. Starts new server (for HTTP/SSE modes)
6. Saves new configuration to `.mcp_transport_config`

**Example session:**
```bash
$ ./switch-transport.sh

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
MCP Transport Mode Switcher
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ℹ Current configuration loaded:
  Transport Mode: stdio
  Elasticsearch Host: http://localhost:9200
  Read-Only Mode: true

Do you want to switch to a different transport mode? (y/n): y

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Select New Transport Mode
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Available Transport Modes:

  1) stdio (Standard Input/Output)
     - Recommended for Claude Code CLI
     - Simple, secure, no network ports
     - Server auto-starts/stops with Claude Code

  2) SSE (Server-Sent Events)
     - HTTP endpoint with event streaming
     - Can be accessed via curl/web
     - Requires running as a background service
     - Example: http://localhost:8001/sse

  3) Streamable HTTP
     - Standard HTTP POST requests
     - RESTful API access
     - Requires running as a background service
     - Example: http://localhost:8001/mcp

Select transport mode (1, 2, or 3): 2
Enter SSE server port [8001]: 8001
✓ Selected: SSE mode on port 8001

⚠ This will:
⚠   1. Stop any running background MCP server
⚠   2. Update Claude Code configuration
⚠   3. Start new server (for HTTP/SSE modes)

Proceed with switching to sse mode? (y/n): y

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Updating Claude Code Configuration
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ℹ Removing old MCP server configuration...
ℹ Configuring SSE transport on port 8001
✓ Claude Code configuration updated

ℹ Saving new configuration...
✓ Configuration saved to /path/to/.mcp_transport_config

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Starting Background MCP Server
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ℹ Starting sse server on port 8001...
✓ MCP server started successfully (PID: 123456)
ℹ Server running on http://localhost:8001/sse
ℹ Logs: /path/to/mcp-server.log
ℹ Testing endpoint: http://localhost:8001/sse
✓ Server endpoint is accessible!

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Transport Mode Switch Complete
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Configuration Summary:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Transport Mode: sse
  Server Port: 8001
  Endpoint: http://localhost:8001/sse

Next Steps:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  For Claude Code CLI:
    1. Restart Claude Code (if currently running)
    2. Type '/mcp' in Claude Code
    3. Select 'crowdsentinel' from the list

  For HTTP/curl access:
    curl http://localhost:8001/sse

  Server management:
    Stop: kill $(cat .mcp_server_pid)
    Logs: tail -f mcp-server.log

✓ Transport mode successfully switched to sse!
```

---

## Manual Configuration

### Editing Claude Code Configuration

You can manually edit the MCP server configuration:

```bash
nano ~/.claude.json
```

Find the `crowdsentinel` section and update the `args` array:

**For stdio:**
```json
"args": [
  "--directory",
  "/path/to/crowdsentinel-mcp-server",
  "run",
  "crowdsentinel-mcp-server"
]
```

**For SSE:**
```json
"args": [
  "--directory",
  "/path/to/crowdsentinel-mcp-server",
  "run",
  "crowdsentinel-mcp-server",
  "--transport",
  "sse",
  "--port",
  "8001"
]
```

**For Streamable HTTP:**
```json
"args": [
  "--directory",
  "/path/to/crowdsentinel-mcp-server",
  "run",
  "crowdsentinel-mcp-server",
  "--transport",
  "streamable-http",
  "--port",
  "8001"
]
```

---

## Background Server Management

### For SSE and Streamable HTTP modes:

**Start server:**
```bash
cd /path/to/crowdsentinel-mcp-server

ELASTICSEARCH_HOSTS="http://localhost:9200" \
ELASTICSEARCH_USERNAME="elastic" \
ELASTICSEARCH_PASSWORD="your-password" \
VERIFY_CERTS="false" \
DISABLE_HIGH_RISK_OPERATIONS="true" \
nohup uv run crowdsentinel-mcp-server \
  --transport sse \
  --port 8001 \
  > mcp-server.log 2>&1 &

echo $! > .mcp_server_pid
```

**Check server status:**
```bash
# Check if server is running
ps -p $(cat .mcp_server_pid)

# View logs
tail -f mcp-server.log

# Test endpoint (SSE)
curl http://localhost:8001/sse

# Test endpoint (HTTP)
curl -X POST http://localhost:8001/mcp
```

**Stop server:**
```bash
# Graceful stop
kill $(cat .mcp_server_pid)

# Force stop if needed
kill -9 $(cat .mcp_server_pid)

# Clean up
rm .mcp_server_pid
```

---

## Use Cases

### Scenario 1: Local Threat Hunting with Claude Code

**Best choice:** stdio

**Why:** You're using Claude Code locally and don't need external access. stdio is the simplest and most secure option.

**Setup:**
```bash
./setup.sh
# Choose option 1 (stdio) during setup
```

---

### Scenario 2: Web-Based Threat Hunting Dashboard

**Best choice:** SSE

**Why:** You're building a web dashboard that needs real-time event streaming from the MCP server.

**Setup:**
```bash
./setup.sh
# Choose option 2 (SSE) during setup
# Or switch later: ./switch-transport.sh
```

**Integration example:**
```javascript
// Web dashboard code
const eventSource = new EventSource('http://localhost:8001/sse');

eventSource.onmessage = function(event) {
  const data = JSON.parse(event.data);
  console.log('Received:', data);
  // Update dashboard with threat hunting results
};
```

---

### Scenario 3: API Integration with SOAR Platform

**Best choice:** Streamable HTTP

**Why:** You're integrating with a SOAR (Security Orchestration, Automation, and Response) platform that uses REST APIs.

**Setup:**
```bash
./setup.sh
# Choose option 3 (Streamable HTTP) during setup
# Or switch later: ./switch-transport.sh
```

**Integration example:**
```python
# SOAR playbook integration
import requests

response = requests.post(
    'http://localhost:8001/mcp',
    json={
        'method': 'tools/call',
        'params': {
            'name': 'hunt_by_timeframe',
            'arguments': {
                'index': 'winlogbeat-*',
                'timeframe': '1h'
            }
        }
    }
)

results = response.json()
print(f"Threats found: {results}")
```

---

## Troubleshooting

### Port Already in Use

**Error:**
```
Port 8001 is in use (PID: 123456)
```

**Solution:**
```bash
# Kill existing process
kill $(lsof -ti:8001)

# Or use switch script (handles this automatically)
./switch-transport.sh
```

---

### Server Not Starting

**Check logs:**
```bash
tail -f mcp-server.log
```

**Common issues:**
- Elasticsearch not running
- Invalid credentials
- Port already in use
- Insufficient permissions

---

### Claude Code Not Connecting

**Solution:**
1. Restart Claude Code
2. Verify configuration:
   ```bash
   cat ~/.claude.json | grep crowdsentinel
   ```
3. Check server status (for HTTP/SSE modes):
   ```bash
   ps -p $(cat .mcp_server_pid)
   ```

---

## Security Considerations

### stdio Mode
- ✅ Most secure (no network exposure)
- ✅ No authentication needed
- ✅ Local process isolation

### SSE/HTTP Modes
- ⚠️ Network port exposed
- ⚠️ Consider adding authentication
- ⚠️ Use SSL/TLS in production
- ⚠️ Restrict to localhost in production
- ⚠️ Use firewall rules to limit access

**Production recommendations for HTTP/SSE:**
```bash
# Bind to localhost only (not 0.0.0.0)
uv run crowdsentinel-mcp-server --transport sse --host 127.0.0.1 --port 8001

# Use reverse proxy with authentication (nginx, Apache)
# Enable SSL/TLS
# Use API keys or OAuth for authentication
```

---

## Summary

- **stdio**: Best for local Claude Code usage, simplest and most secure
- **SSE**: Best for web integrations and real-time event streaming
- **Streamable HTTP**: Best for REST API integrations and automation

**Switch anytime using:**
```bash
./switch-transport.sh
```

**Questions?** See [FIRST_TIME_SETUP.md](FIRST_TIME_SETUP.md) for comprehensive setup guide.
