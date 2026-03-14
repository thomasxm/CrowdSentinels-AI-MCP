<!-- mcp-name: io.github.thomasxm/crowdsentinel-mcp-server -->

<div align="center">
  <img src="logo.png" alt="CrowdSentinel Logo" width="400"/>

# CrowdSentinel MCP Server

### AI-Powered Threat Hunting & Incident Response Framework

[![PyPI](https://img.shields.io/pypi/v/crowdsentinel-mcp-server.svg)](https://pypi.org/project/crowdsentinel-mcp-server/)
[![PyPI Downloads](https://img.shields.io/pypi/dm/crowdsentinel-mcp-server.svg)](https://pypi.org/project/crowdsentinel-mcp-server/)
[![Python](https://img.shields.io/pypi/pyversions/crowdsentinel-mcp-server.svg)](https://pypi.org/project/crowdsentinel-mcp-server/)
[![License](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](LICENSE)
[![MCP](https://img.shields.io/badge/MCP-Compatible-purple.svg)](https://modelcontextprotocol.io/)
[![Tools](https://img.shields.io/badge/MCP%20Tools-79-brightgreen.svg)](https://github.com/thomasxm/CrowdSentinels-AI-MCP)
[![Rules](https://img.shields.io/badge/Detection%20Rules-5%2C049-blue.svg)](https://github.com/thomasxm/CrowdSentinels-AI-MCP)
[![Stars](https://img.shields.io/github/stars/thomasxm/CrowdSentinels-AI-MCP?style=social)](https://github.com/thomasxm/CrowdSentinels-AI-MCP)

**Open-source threat hunting orchestrator connecting LLMs to enterprise security data via Model Context Protocol (MCP)**

[Quick Start](#quick-start) · [Installation](#installation) · [CLI Usage](#cli-usage) · [Features](#key-features) · [Architecture](#architecture) · [Documentation](#documentation) · [Examples](#usage-examples)

</div>

---

## What is CrowdSentinel?

**CrowdSentinel** transforms traditional SIEM querying into intelligent, framework-driven investigations using natural language. It serves as a unified security intelligence layer that connects large language models to enterprise security data sources, enabling:

- **Natural Language Threat Hunting** — Query Elasticsearch using plain English
- **AI-Guided Investigation Workflows** — Built-in prompts guide agents through proper IR methodology
- **Cross-Tool IoC Correlation** — IoCs discovered in one tool are available to all others
- **Multi-Source Analysis** — Elasticsearch, EVTX logs (Chainsaw), PCAP files (Wireshark)
- **Standalone CLI** — Full threat hunting from the terminal without an MCP client

---

<a name="installation"></a>
## Installation

### Install from PyPI

```bash
# Install with pip
pip install crowdsentinel-mcp-server

# Or install with uv (recommended)
uv pip install crowdsentinel-mcp-server
```

### Run directly with uvx (no install needed)

```bash
# Elasticsearch 8.x (default)
uvx crowdsentinel-mcp-server

# Other backends
uvx crowdsentinel-mcp-server-es7   # Elasticsearch 7.x
uvx crowdsentinel-mcp-server-es9   # Elasticsearch 9.x
uvx opensearch-mcp-server          # OpenSearch 1.x/2.x/3.x
```

### Install from source

```bash
git clone https://github.com/thomasxm/CrowdSentinels-AI-MCP.git
cd CrowdSentinels-AI-MCP
uv sync
uv run crowdsentinel-mcp-server
```

### Automated setup (recommended for first-time users)

```bash
git clone https://github.com/thomasxm/CrowdSentinels-AI-MCP.git
cd CrowdSentinels-AI-MCP
chmod +x setup.sh && ./setup.sh
```

The setup script will:
- Install dependencies (pipx, uv, Claude Code CLI if needed)
- Download 5,049 detection rules and Chainsaw binary
- Prompt for Elasticsearch credentials (never hardcoded)
- Configure the MCP server with Claude Code
- Validate your connection

---

<a name="quick-start"></a>
## Quick Start

### 1. Set environment variables

```bash
export ELASTICSEARCH_HOSTS="https://localhost:9200"
export ELASTICSEARCH_API_KEY="your_api_key"
# Or use username/password:
# export ELASTICSEARCH_USERNAME="elastic"
# export ELASTICSEARCH_PASSWORD="your_password"
export VERIFY_CERTS="false"
```

### 2. Use as MCP Server

```json
{
  "mcpServers": {
    "crowdsentinel": {
      "command": "uvx",
      "args": ["crowdsentinel-mcp-server"],
      "env": {
        "ELASTICSEARCH_HOSTS": "https://localhost:9200",
        "ELASTICSEARCH_API_KEY": "your_api_key",
        "VERIFY_CERTS": "false"
      }
    }
  }
}
```

### 3. Or use the CLI directly

```bash
# Check cluster health
crowdsentinel health

# Hunt for threats
crowdsentinel hunt "powershell encoded" -i winlogbeat-*

# Run a detection rule
crowdsentinel detect windows_builtin_win_security_susp_logon_eql -i winlogbeat-*

# List detection rules
crowdsentinel rules -p windows --tactic credential_access
```

---

<a name="cli-usage"></a>
## CLI Usage

CrowdSentinel provides a full CLI for threat hunting from the terminal. Install via `pip install crowdsentinel-mcp-server`, then:

```bash
crowdsentinel --help
crowdsentinel --version
```

### Available Commands

| Command | Description | Example |
|:--------|:------------|:--------|
| `health` | Show cluster health | `crowdsentinel health` |
| `indices` | List all indices | `crowdsentinel indices` |
| `hunt` | IR-focused threat hunt with IoC extraction | `crowdsentinel hunt "powershell" -i winlogbeat-*` |
| `eql` | Execute an EQL query | `crowdsentinel eql "process where process.name == 'cmd.exe'" -i winlogbeat-*` |
| `esql` | Execute an ES\|QL query | `crowdsentinel esql "FROM logs-* \| LIMIT 10"` |
| `detect` | Execute a detection rule by ID | `crowdsentinel detect win_susp_logon -i winlogbeat-*` |
| `rules` | List available detection rules | `crowdsentinel rules -p windows --tactic credential_access` |
| `schema` | Detect schema for an index pattern | `crowdsentinel schema -i winlogbeat-*` |
| `ioc` | Hunt for a specific Indicator of Compromise | `crowdsentinel ioc 203.0.113.42 --type ip -i winlogbeat-*` |
| `analyse` | Analyse search results from stdin (JSON) | `cat results.json \| crowdsentinel analyse -c "context"` |

### Output Formats

All commands support `--output/-o` with three formats:

```bash
crowdsentinel hunt "failed login" -i winlogbeat-* -o json     # Structured JSON (default)
crowdsentinel hunt "failed login" -i winlogbeat-* -o table    # Human-readable table
crowdsentinel hunt "failed login" -i winlogbeat-* -o summary  # Condensed summary
```

### Pipeline Example

```bash
# Hunt then analyse (mirrors the MCP investigation workflow)
crowdsentinel hunt "powershell encoded" -i winlogbeat-* -o json | \
  crowdsentinel analyse -c "Encoded PowerShell commands" -o summary
```

---

<a name="key-features"></a>
## Key Features

<table>
<tr>
<td width="50%">

### 79 MCP Tools
Threat hunting, detection rules, forensics, network analysis — all accessible via natural language

### 5,049 Detection Rules
Pre-built Lucene & EQL rules with automatic MITRE ATT&CK mapping

### Investigation State
Persistent IoC tracking across tools and sessions with FIFO storage

</td>
<td width="50%">

### 4 Security Frameworks
- Cyber Kill Chain (7 stages)
- Pyramid of Pain (6 levels)
- Diamond Model (4 vertices)
- MITRE ATT&CK (automatic mapping)

### 3 Data Sources
- Elasticsearch / OpenSearch
- EVTX logs (Chainsaw + Sigma)
- PCAP files (Wireshark/TShark)

</td>
</tr>
</table>

---

<a name="architecture"></a>
## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                 LLM Client / Claude Code CLI                    │
└─────────────────────────────┬───────────────────────────────────┘
                              │ MCP Protocol (stdio/SSE/HTTP)
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    CrowdSentinel MCP Server                      │
│  ┌───────────────┐ ┌───────────────┐ ┌───────────────────────┐  │
│  │   79 Tools    │ │ 5,049 Rules   │ │ Security Frameworks   │  │
│  │ - Hunting     │ │ - Lucene      │ │ - Cyber Kill Chain    │  │
│  │ - Detection   │ │ - EQL         │ │ - Pyramid of Pain     │  │
│  │ - Forensics   │ │ - Sigma       │ │ - Diamond Model       │  │
│  │ - Network     │ │               │ │ - MITRE ATT&CK        │  │
│  └───────────────┘ └───────────────┘ └───────────────────────┘  │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │              Investigation State (Persistent)                ││
│  │         Cross-tool IoC sharing, timeline, reporting         ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────┬───────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│ Elasticsearch │    │   Chainsaw    │    │   Wireshark   │
│  /OpenSearch  │    │  (EVTX/Sigma) │    │    (PCAP)     │
└───────────────┘    └───────────────┘    └───────────────┘
        │
        ▼ (Roadmap)
┌───────────────┐
│    Splunk     │
└───────────────┘
```

---

## What's Included

### Tool Categories (79 Tools)

| Category | Tools | Description |
|:---------|:-----:|:------------|
| **Elasticsearch Core** | 18 | Index, document, cluster, alias, data stream operations |
| **Threat Hunting** | 12 | Attack pattern detection, IoC hunting, timeline analysis |
| **Detection Rules** | 9 | 5,049 rule library — list, execute, validate, suggest |
| **Kill Chain Analysis** | 5 | Stage hunting, progression tracking, adjacent stage prediction |
| **Investigation Prompts** | 5 | Fast triage spine — 10 critical IR questions |
| **Chainsaw (EVTX)** | 6 | Sigma rule hunting, iterative IoC discovery |
| **Wireshark (PCAP)** | 11 | Network forensics, beaconing, lateral movement detection |
| **Investigation State** | 13 | Persistent IoCs, cross-tool sharing, export, reporting |

### Security Frameworks

| Framework | Purpose |
|:----------|:--------|
| **Cyber Kill Chain** | Hunt by attack stage (7 stages), predict adversary's next move |
| **Pyramid of Pain** | Prioritise IoCs by difficulty for attackers to change (6 levels) |
| **Diamond Model** | Map adversary, capability, infrastructure, victim relationships |
| **MITRE ATT&CK** | Automatic technique mapping for all detections |

### Detection Rules (5,049 Rules)

| Type | Count | Description |
|:-----|------:|:------------|
| **Lucene** | 1,968 | Fast pattern matching queries |
| **EQL** | 3,081 | Event sequences and correlations |

**Platforms:** Windows, Linux, macOS, Cloud (AWS/Azure/GCP), Network

**Log Sources:** PowerShell, Sysmon, Security Events, Process Creation, Audit logs

---

## Configuration

### Environment Variables

```bash
# Connection (required)
ELASTICSEARCH_HOSTS="https://localhost:9200"

# Authentication — choose one:
ELASTICSEARCH_API_KEY="your_api_key"        # Recommended
# OR
ELASTICSEARCH_USERNAME="elastic"
ELASTICSEARCH_PASSWORD="your_password"

# Options
VERIFY_CERTS="false"                        # SSL certificate verification
REQUEST_TIMEOUT="30"                        # Request timeout in seconds
DISABLE_HIGH_RISK_OPERATIONS="true"         # Block all write operations
```

### Transport Modes

| Mode | Use Case | Command |
|:-----|:---------|:--------|
| **stdio** (default) | MCP clients (Claude Code, etc.) | Auto-configured by setup.sh |
| **SSE** | Web/streaming clients | `--transport sse --port 8000` |
| **HTTP** | REST API access | `--transport streamable-http` |

### Disabling Write Operations

For read-only access (recommended for production):

```bash
DISABLE_HIGH_RISK_OPERATIONS="true"
```

This hides destructive tools: `create_index`, `delete_index`, `index_document`, `delete_document`, `delete_by_query`, `create_data_stream`, `delete_data_stream`, `put_alias`, `delete_alias`, `general_api_request`

---

<a name="usage-examples"></a>
## Usage Examples

### Example 1: Hunt for Brute Force Attacks

```
You: Hunt for brute force attacks in the last hour

CrowdSentinel: Searching for failed authentication attempts...
[Calls hunt_by_timeframe with attack_types=["brute_force"]]

Found 47 failed login attempts from 3 source IPs targeting the "admin" account.
Top sources:
- 192.168.1.105: 28 attempts
- 10.0.0.42: 15 attempts
- 172.16.0.8: 4 attempts
```

### Example 2: Investigate a Suspicious Host

```
You: Show me all activity on host DESKTOP-ABC123 in the last 24 hours

CrowdSentinel: Generating a forensic timeline for that host...
[Calls get_host_activity_timeline]

Timeline shows:
- 09:15: User "jsmith" logged in (Event 4624)
- 09:17: PowerShell executed encoded command
- 09:18: New scheduled task created "WindowsUpdate"
- 09:22: Outbound connection to 203.0.113.42:443
- 09:25: LSASS memory access detected
```

### Example 3: Kill Chain Analysis

```
You: We found C2 beaconing. What should we hunt for next?

CrowdSentinel: Hunting adjacent kill chain stages...
[Calls hunt_adjacent_stages with current_stage="COMMAND_AND_CONTROL"]

Looking backwards (Installation stage):
- Found scheduled task persistence on 3 hosts
- Registry Run key modifications detected

Looking forwards (Actions on Objectives):
- Lateral movement to 2 additional hosts via SMB
- Credential dumping attempts detected
```

### Example 4: Network Traffic Analysis

```
You: Analyse this PCAP for C2 beaconing

CrowdSentinel: Checking for regular connection intervals...
[Calls detect_beaconing on the PCAP file]

Detected beaconing pattern:
- Host: 192.168.1.50 → 203.0.113.100:443
- Interval: 60 seconds (±2s jitter)
- Duration: 4 hours
- Confidence: HIGH

Recommend blocking 203.0.113.100 and investigating 192.168.1.50.
```

### Example 5: CLI Threat Hunt

```bash
# Hunt for encoded PowerShell
crowdsentinel hunt "powershell -enc" -i winlogbeat-* --timeframe 1440 -o json

# Pipe results to analysis
crowdsentinel hunt "event.code:4625" -i winlogbeat-* -o json | \
  crowdsentinel analyse -c "Failed authentication investigation"

# Search detection rules for lateral movement
crowdsentinel rules --tactic lateral_movement -p windows
```

---

## Compatibility

| Package | Backend | Install |
|:--------|:--------|:--------|
| `crowdsentinel-mcp-server` | Elasticsearch 8.x (default) | `pip install crowdsentinel-mcp-server` |
| `crowdsentinel-mcp-server-es7` | Elasticsearch 7.x | `pip install crowdsentinel-mcp-server-es7` |
| `crowdsentinel-mcp-server-es9` | Elasticsearch 9.x | `pip install crowdsentinel-mcp-server-es9` |
| `opensearch-mcp-server` | OpenSearch 1.x, 2.x, 3.x | `pip install opensearch-mcp-server` |

---

## For Developers

<details>
<summary><b>Project Structure</b></summary>

```
crowdsentinel-mcp-server/
├── src/
│   ├── server.py                 # MCP server entry point
│   ├── version.py                # Version constant
│   ├── risk_config.py            # Write operation controls
│   │
│   ├── cli/                      # Standalone CLI
│   │   └── main.py               # CLI entry point (argparse)
│   │
│   ├── clients/                  # Backend logic layer
│   │   ├── base.py               # Base client, authentication
│   │   ├── exceptions.py         # Exception handling decorators
│   │   └── common/
│   │       ├── client.py         # Unified SearchClient (multiple inheritance)
│   │       ├── threat_hunting.py # Threat hunting queries
│   │       ├── ioc_analysis.py   # IoC extraction & analysis
│   │       ├── cyber_kill_chain.py # Kill chain logic
│   │       ├── rule_loader.py    # Detection rule loading
│   │       └── chainsaw_client.py # EVTX/Sigma integration
│   │
│   ├── tools/                    # MCP tool interfaces (thin wrappers)
│   │   ├── register.py           # Dynamic tool registration
│   │   ├── threat_hunting.py     # Hunting tool definitions
│   │   ├── rule_management.py    # Rule management tools
│   │   ├── chainsaw_hunting.py   # Chainsaw tools
│   │   ├── wireshark_tools.py    # Network analysis tools
│   │   └── investigation_state_tools.py # State management tools
│   │
│   ├── storage/                  # Persistent investigation state
│   │   ├── investigation_state.py # Core state management
│   │   ├── storage_manager.py    # File system storage (8GB FIFO)
│   │   └── models.py             # Pydantic models (IoC, Investigation)
│   │
│   └── wireshark/                # Network traffic analysis
│       ├── core/                 # TShark execution, PCAP parsing
│       ├── hunting/              # Beaconing, lateral movement, IoC hunting
│       ├── baseline/             # Traffic baseline creation
│       ├── extraction/           # File carving from traffic
│       └── reporting/            # NCSC-style reports, timelines
│
├── rules/                        # 5,049 detection rules (EQL + Lucene)
├── chainsaw/                     # Chainsaw binary + 3,000+ Sigma rules
├── skills/                       # Claude Code agent skills
└── tests/                        # Test suites
```

</details>

<details>
<summary><b>Design Patterns</b></summary>

| Pattern | Usage |
|:--------|:------|
| **Multiple Inheritance** | `SearchClient` composes all specialised clients |
| **Decorator** | Exception handling via `@handle_exceptions` |
| **Factory** | `create_search_client()` creates appropriate client |
| **Plugin Architecture** | Tools registered dynamically via `ToolsRegister` |
| **Auto-Capture** | Tool results automatically analysed for IoCs |

</details>

<details>
<summary><b>Adding a New Tool</b></summary>

1. **Create client method** in `src/clients/common/your_module.py`:
```python
class YourClient(SearchClientBase):
    def your_method(self, param: str) -> dict:
        # Implementation
        return results
```

2. **Add to SearchClient** in `src/clients/common/client.py`:
```python
class SearchClient(YourClient, OtherClients, ...):
    pass
```

3. **Create tool wrapper** in `src/tools/your_tools.py`:
```python
class YourTools:
    def __init__(self, client, mcp):
        self.client = client
        self.mcp = mcp

    def register_tools(self):
        @self.mcp.tool()
        def your_tool(param: str) -> str:
            """Tool description for LLM."""
            result = self.client.your_method(param)
            return json.dumps(result)
```

4. **Register in server** in `src/server.py`:
```python
from src.tools.your_tools import YourTools

def _register_tools(self):
    # ... existing tools ...
    YourTools(self.client, self.mcp).register_tools()
```

</details>

<details>
<summary><b>Running Tests</b></summary>

```bash
# All tests
uv run pytest

# Specific module
uv run pytest tests/test_investigation_state.py

# With coverage
uv run pytest --cov=src
```

</details>

<details>
<summary><b>Local Testing Environment</b></summary>

```bash
# Start Elasticsearch
docker-compose -f docker-compose-elasticsearch.yml up -d

# Start OpenSearch
docker-compose -f docker-compose-opensearch.yml up -d
```

**Default credentials (testing only):**
- Elasticsearch: `elastic` / `test123`
- OpenSearch: `admin` / `admin`

</details>

---

## Roadmap

| Feature | Status | Description |
|:--------|:------:|:------------|
| **Splunk Integration** | Planned | Add Splunk as a data source alongside Elasticsearch |
| **Sigma Rule Converter** | Planned | Convert Sigma rules to native ES/Splunk queries |
| **Threat Intel Feeds** | Planned | Automatic IoC enrichment from MISP, OTX, etc. |
| **Case Management** | Planned | Export investigations to TheHive, JIRA |
| **Custom Rule Builder** | Planned | Create detection rules via natural language |

See [CHANGELOG.md](CHANGELOG.md) for detailed version history.

---

<a name="documentation"></a>
## Documentation

### User Guides

| Document | Description |
|:---------|:------------|
| [FIRST_TIME_SETUP.md](FIRST_TIME_SETUP.md) | Detailed first-time setup instructions |
| [HOW_TO_USE.md](HOW_TO_USE.md) | Comprehensive usage guide |
| [QUICK_START.md](QUICK_START.md) | 5-minute quick start |
| [TRANSPORT_MODES.md](TRANSPORT_MODES.md) | stdio, SSE, HTTP configuration |

### Feature Guides

| Document | Description |
|:---------|:------------|
| [THREAT_HUNTING_GUIDE.md](THREAT_HUNTING_GUIDE.md) | Threat hunting workflows |
| [DETECTION_RULES_GUIDE.md](DETECTION_RULES_GUIDE.md) | Using 5,049 detection rules |
| [CYBER_KILL_CHAIN_GUIDE.md](CYBER_KILL_CHAIN_GUIDE.md) | Kill chain analysis |
| [CHAINSAW_GUIDE.md](CHAINSAW_GUIDE.md) | EVTX log analysis with Sigma |
| [INVESTIGATION_PROMPTS_GUIDE.md](INVESTIGATION_PROMPTS_GUIDE.md) | Fast triage spine |
| [AI_AGENT_INTEGRATION.md](AI_AGENT_INTEGRATION.md) | Workflow guidance for AI agents |

### Developer Guides

| Document | Description |
|:---------|:------------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Detailed architecture documentation |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contribution guidelines |

---

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## Licence

GNU General Public Licence v3.0 — See [LICENSE](LICENSE) for details.

---

## Acknowledgements

- **MCP Framework:** [Model Context Protocol](https://modelcontextprotocol.io/) by Anthropic
- **Chainsaw:** EVTX log analyser by [WithSecure Labs](https://github.com/WithSecureLabs/chainsaw)
- **Detection Rules:** Community-contributed Sigma and custom rules
- **Frameworks:** Cyber Kill Chain (Lockheed Martin), Pyramid of Pain (David J. Bianco), Diamond Model, MITRE ATT&CK

---

<div align="center">

**Made for the security community by [medjedtxm](https://github.com/thomasxm)**

[![GitHub](https://img.shields.io/badge/GitHub-CrowdSentinel-181717?style=for-the-badge&logo=github)](https://github.com/thomasxm/CrowdSentinels-AI-MCP)
[![PyPI](https://img.shields.io/badge/PyPI-crowdsentinel--mcp--server-3775A9?style=for-the-badge&logo=pypi&logoColor=white)](https://pypi.org/project/crowdsentinel-mcp-server/)

</div>
