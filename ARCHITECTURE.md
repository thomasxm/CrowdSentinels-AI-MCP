# CrowdSentinel MCP Server - Architecture & Implementation Guide

## Table of Contents
1. [Project Overview](#project-overview)
2. [Architecture Design](#architecture-design)
3. [Core Components](#core-components)
4. [MCP Implementation Details](#mcp-implementation-details)
5. [Tool System](#tool-system)
6. [Client System](#client-system)
7. [Security & Risk Management](#security--risk-management)
8. [Configuration System](#configuration-system)
9. [Adding New Features](#adding-new-features)
10. [API Reference](#api-reference)

---

## Project Overview

### What is This Project?
The CrowdSentinel MCP Server is a **Model Context Protocol (MCP)** server that provides programmatic access to Elasticsearch and OpenSearch clusters. It enables AI assistants and other MCP clients to interact with search engines through a standardised protocol.

### Key Metadata
- **Version**: 0.3.4
- **Language**: Python 3.10+
- **Protocol**: MCP (Model Context Protocol)
- **Supported Engines**:
  - Elasticsearch 7.x, 8.x, 9.x
  - OpenSearch 1.x, 2.x, 3.x
- **Licence**: GPL-3.0-only
- **Repository**: https://github.com/thomasxm/CrowdSentinels-AI-MCP

---

## Architecture Design

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    MCP Client (e.g., Claude)                │
└───────────────────────────┬─────────────────────────────────┘
                            │ MCP Protocol
                            │ (stdio/HTTP/SSE)
┌───────────────────────────▼─────────────────────────────────┐
│                     SearchMCPServer                          │
│  ┌──────────────────────────────────────────────────────┐   │
│  │              FastMCP Instance                        │   │
│  │  - Tool Registration                                 │   │
│  │  - Transport Handling                                │   │
│  │  - Request/Response Processing                       │   │
│  └──────────────────────────────────────────────────────┘   │
│                            │                                 │
│  ┌─────────────────────────▼──────────────────────────────┐ │
│  │              ToolsRegister                             │ │
│  │  - Tool Discovery                                      │ │
│  │  - Exception Handling Wrapper                         │ │
│  │  - Risk Filtering                                      │ │
│  └─────────────────────────┬──────────────────────────────┘ │
│                            │                                 │
│  ┌─────────────────────────▼──────────────────────────────┐ │
│  │              Tool Classes (19)                         │ │
│  │                                                        │ │
│  │  Core Tools:                                           │ │
│  │  - IndexTools, DocumentTools, ClusterTools              │ │
│  │  - AliasTools, DataStreamTools, GeneralTools            │ │
│  │                                                        │ │
│  │  Security/Hunting Tools:                               │ │
│  │  - ThreatHuntingTools, SmartSearchTools                 │ │
│  │  - RuleManagementTools, IoCAnalysisTools                │ │
│  │  - EQLQueryTools                                        │ │
│  │                                                        │ │
│  │  Investigation Tools:                                  │ │
│  │  - InvestigationStateTools                              │ │
│  │  - InvestigationPromptsTools                            │ │
│  │  - WorkflowGuidanceTools                                │ │
│  │                                                        │ │
│  │  Analysis Tools:                                       │ │
│  │  - ChainsawHuntingTools, WiresharkTools                 │ │
│  │  - ESQLHuntingTools, AssetDiscoveryTools                │ │
│  │  - SchemaTools                                          │ │
│  └─────────────────────────┬──────────────────────────────┘ │
│                            │                                 │
│  ┌─────────────────────────▼──────────────────────────────┐ │
│  │           SearchClient (Unified)                       │ │
│  │  Multiple Inheritance:                                 │ │
│  │  - IndexClient                                         │ │
│  │  - DocumentClient                                      │ │
│  │  - ClusterClient                                       │ │
│  │  - AliasClient                                         │ │
│  │  - DataStreamClient                                    │ │
│  │  - GeneralClient                                       │ │
│  └─────────────────────────┬──────────────────────────────┘ │
│                            │                                 │
│  ┌─────────────────────────▼──────────────────────────────┐ │
│  │         SearchClientBase                               │ │
│  │  - Elasticsearch/OpenSearch client initialization      │ │
│  │  - Authentication management                           │ │
│  │  - SSL/TLS configuration                               │ │
│  └─────────────────────────┬──────────────────────────────┘ │
└────────────────────────────┼────────────────────────────────┘
                             │
          ┌──────────────────┼──────────────────┐
          │                  │                  │
┌─────────▼──────┐  ┌───────▼────────┐  ┌──────▼──────────┐
│ Elasticsearch  │  │  OpenSearch    │  │ GeneralRest     │
│ Client Library │  │  Client Library│  │ Client (httpx)  │
└─────────┬──────┘  └───────┬────────┘  └──────┬──────────┘
          │                 │                   │
          └─────────────────┼───────────────────┘
                            │
                ┌───────────▼────────────┐
                │  Elasticsearch/        │
                │  OpenSearch Cluster    │
                └────────────────────────┘
```

### Design Principles

1. **Separation of Concerns**: Clear separation between server orchestration, tool registration, client operations, and exception handling.

2. **Multiple Inheritance for Client Composition**: The `SearchClient` uses multiple inheritance to compose specialized client classes, providing a unified interface.

3. **Decorator Pattern**: Exception handling and risk filtering are applied via decorators to avoid code duplication.

4. **Factory Pattern**: `create_search_client()` factory function creates the appropriate client based on engine type.

5. **Plugin Architecture**: Tools are registered dynamically, making it easy to add new tool classes.

---

## Core Components

### Directory Structure

```
crowdsentinel-mcp-server/
├── src/
│   ├── server.py                    # Main server entry point
│   ├── version.py                   # Version constant
│   ├── risk_config.py              # Risk management configuration
│   │
│   ├── clients/                     # Client layer
│   │   ├── __init__.py             # Client factory
│   │   ├── base.py                 # Base client with auth
│   │   ├── exceptions.py           # Exception handling decorators
│   │   └── common/                 # Specialized clients
│   │       ├── client.py           # Unified SearchClient
│   │       ├── index.py            # Index operations
│   │       ├── document.py         # Document operations
│   │       ├── cluster.py          # Cluster operations
│   │       ├── alias.py            # Alias operations
│   │       ├── data_stream.py      # Data stream operations
│   │       └── general.py          # General API requests
│   │
│   └── tools/                       # MCP tools layer
│       ├── register.py             # Tool registration system
│       ├── index.py                # Index tools
│       ├── document.py             # Document tools
│       ├── cluster.py              # Cluster tools
│       ├── alias.py                # Alias tools
│       ├── data_stream.py          # Data stream tools
│       └── general.py              # General tools
│
├── pyproject.toml                   # Project configuration
├── server.json                      # MCP server metadata
├── .env.example                     # Environment template
├── docker-compose-elasticsearch.yml # ES testing environment
└── docker-compose-opensearch.yml    # OpenSearch testing environment
```

### File Responsibilities

| File | Lines | Purpose |
|------|-------|---------|
| `src/server.py` | 167 | Server initialisation, argument parsing, entry points |
| `src/risk_config.py` | 78 | Risk management for write operations |
| `src/clients/__init__.py` | 52 | Client factory with env config loading |
| `src/clients/base.py` | 150 | Base client with authentication & initialisation |
| `src/clients/exceptions.py` | 69 | Exception handling decorators |
| `src/clients/common/client.py` | 27 | Unified client combining all capabilities |
| `src/tools/register.py` | 90 | Tool registration with filtering |

---

## MCP Implementation Details

### What is MCP?

The **Model Context Protocol (MCP)** is a standardised protocol for AI assistants to interact with external tools and data sources. This server implements MCP to expose Elasticsearch/OpenSearch functionality.

### MCP Components Used

1. **Tools**: 79+ tools for threat hunting, detection rules, forensics, and analysis
2. **Resources**: Workflow documentation exposed via MCP resources (e.g., `crowdsentinel://investigation-workflow`)
3. **Prompts**: Investigation starter prompts (e.g., `start-investigation`)
4. **FastMCP Framework**: Uses FastMCP (high-level abstraction over base MCP SDK)
5. **Transport Protocols**: Supports stdio, streamable-http, and SSE

### Workflow Guidance Architecture

CrowdSentinel provides built-in workflow guidance to ensure AI agents follow proper investigation procedures. This is implemented through MCP primitives:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Workflow Guidance Layer                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  MCP Resources                                                   │
│  ├── crowdsentinel://investigation-workflow                      │
│  │   └── Complete workflow documentation                         │
│  └── crowdsentinel://tool-recommendations                        │
│      └── Recommended next steps for each tool                    │
│                                                                  │
│  MCP Prompts                                                     │
│  └── start-investigation                                         │
│      └── Guided investigation starter                            │
│                                                                  │
│  Workflow Tools                                                  │
│  ├── get_investigation_workflow()                                │
│  │   └── Returns complete workflow documentation                 │
│  └── get_next_step(tool_name)                                    │
│      └── Returns recommended next action after a tool            │
│                                                                  │
│  Workflow Hints in Tool Outputs                                  │
│  └── Every search/hunting tool returns a workflow_hint field     │
│      that guides the AI to the next required step                │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Key Files:**
- `src/tools/workflow_guidance.py` - MCP resources, prompts, and workflow tools
- `src/tools/smart_search.py` - Workflow hints in search tool outputs
- `src/clients/common/eql_query.py` - Workflow hints in EQL tool outputs

**The Iron Law:**
```
NO INVESTIGATION IS COMPLETE WITHOUT ANALYSIS TOOLS
```

Workflow guidance ensures AI agents always use analysis tools (`analyze_search_results`, `analyze_kill_chain_stage`, `generate_investigation_report`) after data collection.

### Server Initialisation Flow

```python
# src/server.py:17-36
class SearchMCPServer:
    def __init__(self, engine_type):
        # 1. Set engine type (elasticsearch/opensearch)
        self.engine_type = engine_type
        self.name = f"{engine_type}-mcp-server"

        # 2. Initialize FastMCP instance
        self.mcp = FastMCP(self.name)

        # 3. Configure logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        )

        # 4. Create search client (factory pattern)
        self.search_client = create_search_client(self.engine_type)

        # 5. Register all tools
        self._register_tools()
```

### Transport Modes

The server supports three transport protocols:

#### 1. **stdio** (Default)
- Standard input/output communication
- Used by desktop MCP clients (e.g., Claude Desktop)
- Command: `crowdsentinel-mcp-server` (no args)

#### 2. **streamable-http**
- HTTP-based transport with streaming
- Useful for web-based clients
- Command: `crowdsentinel-mcp-server --transport streamable-http --port 8000`
- Default path: `/mcp`

#### 3. **sse** (Server-Sent Events)
- Server-sent events for real-time updates
- Command: `crowdsentinel-mcp-server --transport sse --port 8000`
- Default path: `/sse`

### Entry Points

The project defines two entry points in `pyproject.toml:23-24`:

```toml
[project.scripts]
crowdsentinel-mcp-server = "src.server:elasticsearch_mcp_server"
opensearch-mcp-server = "src.server:opensearch_mcp_server"
```

These create executable commands that launch the server with the appropriate engine type.

---

## Tool System

### Tool Architecture

Tools are the primary interface for MCP clients to interact with the search engine. Each tool:
1. Is registered with the MCP server via `@mcp.tool()` decorator
2. Has exception handling applied automatically
3. Can be filtered based on risk level
4. Returns JSON-serialisable dictionaries

### Tool Registration Flow

```
┌──────────────────────────────────────────────────────────┐
│ SearchMCPServer._register_tools()                        │
└───────────────────┬──────────────────────────────────────┘
                    │
                    │ Creates ToolsRegister instance
                    │
┌───────────────────▼──────────────────────────────────────┐
│ ToolsRegister.register_all_tools(tool_classes)           │
│                                                           │
│ For each tool class:                                     │
│   1. Instantiate tool class                              │
│   2. Set logger and search_client attributes             │
│   3. Check if risk management enabled                    │
│   4a. If enabled: Apply risk filtering + exception       │
│   4b. If disabled: Apply exception handling only         │
│   5. Call tool_instance.register_tools(mcp)              │
└───────────────────┬──────────────────────────────────────┘
                    │
                    │ For each method in tool class
                    │
┌───────────────────▼──────────────────────────────────────┐
│ Tool Class (e.g., IndexTools)                            │
│                                                           │
│ @mcp.tool()  ← Wrapped with exception handler            │
│ def list_indices() -> List[Dict]:                        │
│     return self.search_client.list_indices()             │
└───────────────────────────────────────────────────────────┘
```

### Available Tools (18 Total)

#### Index Tools (4)
| Tool | Risk Level | Description |
|------|-----------|-------------|
| `list_indices()` | Low | List all indices in the cluster |
| `get_index(index)` | Low | Get mappings, settings, and aliases for an index |
| `create_index(index, body)` | **HIGH** | Create a new index with optional settings |
| `delete_index(index)` | **HIGH** | Delete an index (irreversible) |

#### Document Tools (5)
| Tool | Risk Level | Description |
|------|-----------|-------------|
| `search_documents(index, body)` | Low | Search documents using query DSL |
| `get_document(index, id)` | Low | Retrieve a single document by ID |
| `index_document(index, document, id)` | **HIGH** | Create or update a document |
| `delete_document(index, id)` | **HIGH** | Delete a document by ID |
| `delete_by_query(index, body)` | **HIGH** | Delete documents matching a query |

#### Cluster Tools (2)
| Tool | Risk Level | Description |
|------|-----------|-------------|
| `get_cluster_health()` | Low | Get cluster health status |
| `get_cluster_stats()` | Low | Get cluster statistics |

#### Alias Tools (4)
| Tool | Risk Level | Description |
|------|-----------|-------------|
| `list_aliases()` | Low | List all aliases |
| `get_alias(index)` | Low | Get aliases for a specific index |
| `put_alias(index, name, body)` | **HIGH** | Create or update an alias |
| `delete_alias(index, name)` | **HIGH** | Delete an alias |

#### Data Stream Tools (3)
| Tool | Risk Level | Description |
|------|-----------|-------------|
| `get_data_stream(name)` | Low | Get data stream information |
| `create_data_stream(name)` | **HIGH** | Create a new data stream |
| `delete_data_stream(name)` | **HIGH** | Delete a data stream |

#### General Tools (1)
| Tool | Risk Level | Description |
|------|-----------|-------------|
| `general_api_request(method, path, params, body)` | **HIGH** | Execute arbitrary API requests |

### Tool Implementation Pattern

All tool classes follow this pattern (from `src/tools/index.py:5-44`):

```python
class IndexTools:
    def __init__(self, search_client):
        self.search_client = search_client

    def register_tools(self, mcp: FastMCP):
        @mcp.tool()
        def list_indices() -> List[Dict]:
            """List all indices."""
            return self.search_client.list_indices()

        @mcp.tool()
        def get_index(index: str) -> Dict:
            """
            Returns information about an index.

            Args:
                index: Name of the index
            """
            return self.search_client.get_index(index=index)

        # ... more tools
```

**Key Characteristics**:
- Thin wrappers around SearchClient methods
- Type hints for parameters and return values
- Docstrings for MCP client documentation
- Direct pass-through to client (no business logic)

### Exception Handling System

All tools are wrapped with exception handling via the `handle_search_exceptions` decorator (from `src/clients/exceptions.py:10-29`):

```python
def handle_search_exceptions(func: Callable[..., T]) -> Callable[..., list[TextContent]]:
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        logger = logging.getLogger()
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"Unexpected error in {func.__name__}: {e}")
            return [TextContent(type="text", text=f"Unexpected error in {func.__name__}: {str(e)}")]

    return wrapper
```

**What This Does**:
- Catches ALL exceptions from tool execution
- Logs the error with function name
- Returns error message as TextContent (MCP format)
- Prevents server crashes from tool failures

---

## Client System

### Client Architecture Overview

The client system uses **multiple inheritance** to compose a unified client from specialized client classes:

```python
# src/clients/common/client.py:10-27
class SearchClient(
    IndexClient,
    DocumentClient,
    ClusterClient,
    AliasClient,
    DataStreamClient,
    GeneralClient
):
    """Unified search client combining all functionality."""

    def __init__(self, config: Dict, engine_type: str):
        super().__init__(config, engine_type)
```

### Inheritance Hierarchy

```
SearchClientBase (ABC)
    │
    ├─ IndexClient ──────┐
    ├─ DocumentClient ───┤
    ├─ ClusterClient ────┤
    ├─ AliasClient ──────┤──→ SearchClient (combines all)
    ├─ DataStreamClient ─┤
    └─ GeneralClient ────┘
```

### SearchClientBase

The base class handles all initialisation logic (from `src/clients/base.py:10-78`):

**Responsibilities**:
1. Initialise Elasticsearch or OpenSearch client
2. Handle authentication (API key or basic auth)
3. Configure SSL/TLS verification
4. Create GeneralRestClient for arbitrary HTTP requests
5. Suppress SSL warnings when verify_certs=false

**Key Implementation Details**:

```python
class SearchClientBase(ABC):
    def __init__(self, config: Dict, engine_type: str):
        # Extract configuration
        hosts = config.get("hosts")
        api_key = config.get("api_key")
        username = config.get("username")
        password = config.get("password")
        verify_certs = config.get("verify_certs", False)
        timeout = config.get("timeout")

        # Initialize engine-specific client
        if engine_type == "elasticsearch":
            auth_params = self._get_elasticsearch_auth_params(
                username, password, api_key
            )
            self.client = Elasticsearch(
                hosts=hosts,
                verify_certs=verify_certs,
                request_timeout=timeout,
                **auth_params
            )
        elif engine_type == "opensearch":
            self.client = OpenSearch(
                hosts=hosts,
                http_auth=(username, password),
                verify_certs=verify_certs,
                timeout=timeout
            )

        # Create general HTTP client
        self.general_client = GeneralRestClient(...)
```

### Elasticsearch Version Detection

The base client detects the Elasticsearch version to use the correct authentication parameter name (from `src/clients/base.py:80-115`):

```python
def _get_elasticsearch_auth_params(self, username, password, api_key):
    # API key takes precedence
    if api_key:
        return {"api_key": api_key}

    if not username or not password:
        return {}

    # Detect ES version
    from elasticsearch import __version__ as es_version
    major_version = es_version[0]

    if major_version >= 8:
        return {"basic_auth": (username, password)}  # ES 8+
    else:
        return {"http_auth": (username, password)}   # ES 7-
```

**Why This Matters**: Elasticsearch changed the auth parameter name from `http_auth` to `basic_auth` in version 8.0.

### GeneralRestClient

For operations not supported by the official client libraries, a custom HTTP client is provided (from `src/clients/base.py:117-150`):

```python
class GeneralRestClient:
    def __init__(self, base_url, username, password, api_key, verify_certs, timeout):
        self.base_url = base_url.rstrip("/")
        self.auth = (username, password) if username and password else None
        self.api_key = api_key
        self.verify_certs = verify_certs
        self.timeout = timeout

    def request(self, method, path, params=None, body=None):
        url = f"{self.base_url}/{path.lstrip('/')}"
        headers = {}

        # Add API key if provided
        if self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"

        with httpx.Client(verify=self.verify_certs, timeout=self.timeout) as client:
            resp = client.request(
                method=method.upper(),
                url=url,
                params=params,
                json=body,
                auth=self.auth if not self.api_key else None,
                headers=headers
            )
            resp.raise_for_status()

            # Parse JSON response
            if resp.headers.get("content-type", "").startswith("application/json"):
                return resp.json()
            return resp.text
```

**Used By**: `GeneralTools.general_api_request()` for arbitrary API calls.

### Client Factory

The `create_search_client()` factory function creates clients with environment-based configuration (from `src/clients/__init__.py:8-46`):

```python
def create_search_client(engine_type: str) -> SearchClient:
    # Load environment variables
    load_dotenv()

    # Build config from environment
    prefix = engine_type.upper()
    hosts_str = os.environ.get(f"{prefix}_HOSTS", "https://localhost:9200")
    hosts = [host.strip() for host in hosts_str.split(",")]
    username = os.environ.get(f"{prefix}_USERNAME")
    password = os.environ.get(f"{prefix}_PASSWORD")
    api_key = os.environ.get(f"{prefix}_API_KEY")
    verify_certs = os.environ.get("VERIFY_CERTS", "false").lower() == "true"
    timeout = float(os.environ.get("REQUEST_TIMEOUT")) if "REQUEST_TIMEOUT" in os.environ else None

    config = {
        "hosts": hosts,
        "username": username,
        "password": password,
        "api_key": api_key,
        "verify_certs": verify_certs,
        "timeout": timeout
    }

    return SearchClient(config, engine_type)
```

### Specialized Client Classes

Each specialized client class inherits from `SearchClientBase` and implements specific operations:

#### IndexClient (src/clients/common/index.py)
```python
class IndexClient(SearchClientBase):
    def list_indices(self) -> Dict:
        return self.client.cat.indices()

    def get_index(self, index: str) -> Dict:
        return self.client.indices.get(index=index)

    def create_index(self, index: str, body: Optional[Dict] = None) -> Dict:
        return self.client.indices.create(index=index, body=body)

    def delete_index(self, index: str) -> Dict:
        return self.client.indices.delete(index=index)
```

#### DocumentClient (src/clients/common/document.py)

Handles API differences between Elasticsearch and OpenSearch:

```python
class DocumentClient(SearchClientBase):
    def index_document(self, index: str, document: Dict, id: Optional[str] = None) -> Dict:
        if self.engine_type == "elasticsearch":
            # ES uses 'document' parameter
            return self.client.index(index=index, document=document, id=id)
        else:
            # OpenSearch uses 'body' parameter
            return self.client.index(index=index, body=document, id=id)
```

---

## Security & Risk Management

### Risk Management System

The project implements a comprehensive risk management system to prevent accidental or unauthorised write operations.

### RiskManager Class

Located in `src/risk_config.py:33-75`:

```python
class RiskManager:
    def __init__(self):
        self.high_risk_ops_disabled = self._is_high_risk_disabled()

        if self.high_risk_ops_disabled:
            self.disabled_operations = self._get_disabled_operations()
        else:
            self.disabled_operations = set()

    def _is_high_risk_disabled(self) -> bool:
        return os.environ.get("DISABLE_HIGH_RISK_OPERATIONS", "false").lower() == "true"

    def _get_disabled_operations(self) -> Set[str]:
        # Check for custom list first
        custom_ops = os.environ.get("DISABLE_OPERATIONS", "")
        if custom_ops:
            return set(op.strip() for op in custom_ops.split(",") if op.strip())

        # Use default high-risk operations
        all_ops = set()
        for tool_ops in HIGH_RISK_OPERATIONS.values():
            all_ops.update(tool_ops)
        return all_ops

    def is_operation_allowed(self, tool_class_name: str, operation_name: str) -> bool:
        if operation_name in self.disabled_operations:
            return False
        return True
```

### High-Risk Operations

Default high-risk operations (from `src/risk_config.py:10-31`):

```python
HIGH_RISK_OPERATIONS = {
    "IndexTools": {
        "create_index",
        "delete_index",
    },
    "DocumentTools": {
        "index_document",
        "delete_document",
        "delete_by_query",
    },
    "DataStreamTools": {
        "create_data_stream",
        "delete_data_stream",
    },
    "AliasTools": {
        "put_alias",
        "delete_alias",
    },
    "GeneralTools": {
        "general_api_request",  # Can execute any HTTP method
    },
}
```

### Risk Filtering During Registration

When risk management is enabled, tools are filtered during registration (from `src/tools/register.py:52-89`):

```python
def _register_with_risk_filter(self, tool_instance):
    original_tool = self.mcp.tool

    def risk_filter_wrapper(*args, **kwargs):
        decorator = original_tool(*args, **kwargs)

        def risk_check_decorator(func):
            operation_name = func.__name__

            # Check if operation is allowed
            if not risk_manager.is_operation_allowed(
                tool_instance.tool_class_name,
                operation_name
            ):
                # Don't register - return no-op
                def no_op(*args, **kwargs):
                    pass
                return no_op

            # If allowed, use original decorator
            return decorator(func)

        return risk_check_decorator

    try:
        self.mcp.tool = risk_filter_wrapper
        with_exception_handling(tool_instance, self.mcp)
    finally:
        self.mcp.tool = original_tool
```

**Important**: Disabled tools are **completely hidden** from MCP clients. They don't appear in the tool list and cannot be invoked.

### Authentication Security

#### API Key Authentication (Recommended)
```bash
ELASTICSEARCH_API_KEY=<your-api-key>
```

**Advantages**:
- More secure than username/password
- Can be scoped to specific permissions
- Can be rotated without changing credentials
- Takes precedence over basic auth

#### Basic Authentication
```bash
ELASTICSEARCH_USERNAME=elastic
ELASTICSEARCH_PASSWORD=changeme
```

**Handled Differently by Version**:
- ES 8+: Uses `basic_auth` parameter
- ES 7-: Uses `http_auth` parameter
- OpenSearch: Uses `http_auth` parameter

### SSL/TLS Security

```bash
VERIFY_CERTS=true  # Recommended for production
```

**Security Considerations**:
- Default is `false` for development convenience
- **Must be `true` in production**
- When `false`, SSL warnings are suppressed to avoid log noise

### Security Best Practices

1. **Enable High-Risk Operations Filtering in Production**:
   ```bash
   DISABLE_HIGH_RISK_OPERATIONS=true
   ```

2. **Use API Key Authentication**:
   ```bash
   ELASTICSEARCH_API_KEY=<key>
   ```

3. **Enable SSL Verification**:
   ```bash
   VERIFY_CERTS=true
   ```

4. **Configure Request Timeout**:
   ```bash
   REQUEST_TIMEOUT=30  # Prevent DoS via long-running queries
   ```

5. **Use Elasticsearch RBAC**: Configure user roles in Elasticsearch to limit what the API key can do.

6. **Custom Operation Filtering**:
   ```bash
   DISABLE_OPERATIONS=delete_index,delete_by_query,general_api_request
   ```

7. **Network Security**: Run the server in a secure network segment with firewall rules.

---

## Configuration System

### Environment Variables

All configuration is done via environment variables. The server looks for a `.env` file in the working directory.

#### Elasticsearch Configuration

```bash
# Connection
ELASTICSEARCH_HOSTS=https://localhost:9200,https://localhost:9201
VERIFY_CERTS=false
REQUEST_TIMEOUT=30

# Authentication (choose one)
ELASTICSEARCH_API_KEY=<your-api-key>
# OR
ELASTICSEARCH_USERNAME=elastic
ELASTICSEARCH_PASSWORD=changeme

# Risk Management
DISABLE_HIGH_RISK_OPERATIONS=false
DISABLE_OPERATIONS=delete_index,delete_by_query
```

#### OpenSearch Configuration

```bash
# Connection
OPENSEARCH_HOSTS=https://localhost:9200
VERIFY_CERTS=false
REQUEST_TIMEOUT=30

# Authentication
OPENSEARCH_USERNAME=admin
OPENSEARCH_PASSWORD=admin

# Risk Management
DISABLE_HIGH_RISK_OPERATIONS=false
```

### Configuration Loading

Configuration is loaded in `src/clients/__init__.py:8-46`:

1. **Load .env file**: Using `python-dotenv`
2. **Determine prefix**: Based on engine type (ELASTICSEARCH_ or OPENSEARCH_)
3. **Parse hosts**: Split comma-separated list
4. **Parse timeout**: Convert to float if provided
5. **Parse boolean flags**: Convert "true"/"false" strings

### MCP Server Metadata

The `server.json` file provides metadata for MCP clients:

```json
{
  "name": "crowdsentinel-mcp-server",
  "version": "0.3.4",
  "description": "MCP Server for interacting with Elasticsearch and OpenSearch",
  "environment": {
    "ELASTICSEARCH_HOSTS": {
      "type": "string",
      "description": "Comma-separated list of Elasticsearch hosts",
      "default": "https://localhost:9200"
    },
    "ELASTICSEARCH_API_KEY": {
      "type": "string",
      "description": "Elasticsearch API key for authentication"
    },
    ...
  }
}
```

This file is used by MCP clients to display configuration options to users.

---

## Adding New Features

### How to Add a New Tool

Follow these steps to add new MCP tools:

#### Step 1: Create Client Method

Add the client method to an appropriate client class (or create a new one):

```python
# src/clients/common/my_new_client.py
from typing import Dict
from src.clients.base import SearchClientBase

class MyNewClient(SearchClientBase):
    def my_new_operation(self, param1: str, param2: int) -> Dict:
        """Perform my new operation."""
        # Implement using self.client (ES/OS client) or self.general_client
        return self.client.my_api.my_operation(param1=param1, param2=param2)
```

#### Step 2: Add to SearchClient

Update `src/clients/common/client.py` to include your new client:

```python
from src.clients.common.my_new_client import MyNewClient

class SearchClient(
    IndexClient,
    DocumentClient,
    ClusterClient,
    AliasClient,
    DataStreamClient,
    GeneralClient,
    MyNewClient  # Add here
):
    """Unified search client."""
    pass
```

#### Step 3: Create Tool Class

Create a new tool class:

```python
# src/tools/my_new_tool.py
from typing import Dict
from fastmcp import FastMCP

class MyNewTools:
    def __init__(self, search_client):
        self.search_client = search_client

    def register_tools(self, mcp: FastMCP):
        @mcp.tool()
        def my_new_operation(param1: str, param2: int) -> Dict:
            """
            Perform my new operation.

            Args:
                param1: Description of param1
                param2: Description of param2
            """
            return self.search_client.my_new_operation(
                param1=param1,
                param2=param2
            )
```

#### Step 4: Register Tool Class

Add your tool class to the registration list in `src/server.py:44-51`:

```python
tool_classes = [
    IndexTools,
    DocumentTools,
    ClusterTools,
    AliasTools,
    DataStreamTools,
    GeneralTools,
    MyNewTools,  # Add here
]
```

#### Step 5: (Optional) Add Risk Management

If your operation is high-risk, add it to `src/risk_config.py:10-31`:

```python
HIGH_RISK_OPERATIONS = {
    "MyNewTools": {
        "my_new_operation",
    },
    # ... other tools
}
```

#### Step 6: Test Your Tool

1. Start the server:
   ```bash
   crowdsentinel-mcp-server
   ```

2. Connect with an MCP client and test your tool

3. Verify error handling by passing invalid inputs

### How to Add a New MCP Resource

Currently, this server doesn't implement MCP resources. To add resources:

#### Step 1: Define Resource URI Scheme

```python
# In src/server.py
@self.mcp.resource("search://indices/{index}")
def get_index_resource(uri: str) -> str:
    # Parse URI to extract index name
    index = uri.split("/")[-1]

    # Fetch data
    data = self.search_client.get_index(index)

    # Return as string (JSON or text)
    import json
    return json.dumps(data, indent=2)
```

#### Step 2: List Available Resources

```python
@self.mcp.list_resources()
def list_resources() -> list[Resource]:
    indices = self.search_client.list_indices()
    return [
        Resource(
            uri=f"search://indices/{idx['index']}",
            name=idx['index'],
            description=f"Index: {idx['index']}",
            mimeType="application/json"
        )
        for idx in indices
    ]
```

### How to Add a New MCP Prompt

To add prompt templates:

```python
@self.mcp.prompt()
def search_prompt(index: str, query: str) -> str:
    return f"""
    Search the {index} index for: {query}

    Use the search_documents tool with this query structure:
    {{
        "query": {{
            "match": {{
                "_all": "{query}"
            }}
        }}
    }}
    """
```

### How to Support a New Search Engine

To add support for a new search engine (e.g., Apache Solr):

#### Step 1: Install Client Library

```bash
uv add pysolr
```

#### Step 2: Update SearchClientBase

Add initialisation logic in `src/clients/base.py`:

```python
elif engine_type == "solr":
    import pysolr
    self.client = pysolr.Solr(
        hosts[0],
        auth=(username, password),
        verify=verify_certs
    )
```

#### Step 3: Handle API Differences

Update specialized client classes to handle Solr's different API:

```python
# In src/clients/common/document.py
def search_documents(self, index: str, body: Dict) -> Dict:
    if self.engine_type == "solr":
        # Convert ES query to Solr query
        q = self._convert_to_solr_query(body)
        return self.client.search(q)
    else:
        return self.client.search(index=index, body=body)
```

#### Step 4: Add Entry Point

```python
# In pyproject.toml
[project.scripts]
solr-mcp-server = "src.server:solr_mcp_server"

# In src/server.py
def solr_mcp_server():
    args = parse_server_args()
    run_search_server(
        engine_type="solr",
        transport=args.transport,
        host=args.host,
        port=args.port,
        path=args.path
    )
```

---

## API Reference

### MCP Tools API

#### Index Operations

##### `list_indices() -> List[Dict]`
Lists all indices in the cluster.

**Returns**: List of index information dictionaries

**Example**:
```json
[
  {"index": "my-index", "health": "green", "status": "open", "docs.count": "1000"},
  {"index": "logs-2024", "health": "yellow", "status": "open", "docs.count": "50000"}
]
```

##### `get_index(index: str) -> Dict`
Get detailed information about an index.

**Parameters**:
- `index` (str): Name of the index

**Returns**: Dictionary with mappings, settings, and aliases

**Example**:
```json
{
  "my-index": {
    "mappings": {...},
    "settings": {...},
    "aliases": {...}
  }
}
```

##### `create_index(index: str, body: Optional[Dict] = None) -> Dict`
Create a new index.

**Parameters**:
- `index` (str): Name of the index to create
- `body` (dict, optional): Index configuration (mappings, settings)

**Returns**: Acknowledgement dictionary

**Example Body**:
```json
{
  "settings": {
    "number_of_shards": 1,
    "number_of_replicas": 0
  },
  "mappings": {
    "properties": {
      "title": {"type": "text"},
      "timestamp": {"type": "date"}
    }
  }
}
```

##### `delete_index(index: str) -> Dict`
Delete an index (IRREVERSIBLE).

**Parameters**:
- `index` (str): Name of the index to delete

**Returns**: Acknowledgement dictionary

**⚠️ High-Risk Operation**

---

#### Document Operations

##### `search_documents(index: str, body: Dict) -> Dict`
Search for documents using Elasticsearch Query DSL.

**Parameters**:
- `index` (str): Name of the index to search
- `body` (dict): Search query (Elasticsearch Query DSL)

**Returns**: Search results with hits

**Example Body**:
```json
{
  "query": {
    "match": {
      "title": "elasticsearch"
    }
  },
  "size": 10,
  "from": 0,
  "sort": [{"timestamp": "desc"}]
}
```

**Example Return**:
```json
{
  "took": 5,
  "hits": {
    "total": {"value": 42},
    "hits": [
      {"_id": "1", "_source": {"title": "Elasticsearch Guide", "timestamp": "2024-01-01"}},
      ...
    ]
  }
}
```

##### `get_document(index: str, id: str) -> Dict`
Retrieve a document by ID.

**Parameters**:
- `index` (str): Name of the index
- `id` (str): Document ID

**Returns**: Document source

**Example**:
```json
{
  "_id": "1",
  "_source": {
    "title": "Elasticsearch Guide",
    "content": "...",
    "timestamp": "2024-01-01"
  }
}
```

##### `index_document(index: str, document: Dict, id: Optional[str] = None) -> Dict`
Create or update a document.

**Parameters**:
- `index` (str): Name of the index
- `document` (dict): Document data
- `id` (str, optional): Document ID (auto-generated if not provided)

**Returns**: Indexing result

**Example**:
```python
index_document(
    index="my-index",
    document={"title": "Hello World", "timestamp": "2024-01-01"},
    id="doc-1"
)
```

**⚠️ High-Risk Operation**

##### `delete_document(index: str, id: str) -> Dict`
Delete a document by ID.

**Parameters**:
- `index` (str): Name of the index
- `id` (str): Document ID

**Returns**: Deletion result

**⚠️ High-Risk Operation**

##### `delete_by_query(index: str, body: Dict) -> Dict`
Delete all documents matching a query.

**Parameters**:
- `index` (str): Name of the index
- `body` (dict): Query matching documents to delete

**Example Body**:
```json
{
  "query": {
    "range": {
      "timestamp": {
        "lt": "2023-01-01"
      }
    }
  }
}
```

**⚠️ High-Risk Operation** - Can delete many documents at once

---

#### Cluster Operations

##### `get_cluster_health() -> Dict`
Get cluster health status.

**Returns**: Cluster health information

**Example**:
```json
{
  "cluster_name": "my-cluster",
  "status": "green",
  "number_of_nodes": 3,
  "active_primary_shards": 10,
  "active_shards": 20,
  "relocating_shards": 0,
  "initializing_shards": 0,
  "unassigned_shards": 0
}
```

##### `get_cluster_stats() -> Dict`
Get cluster statistics.

**Returns**: Detailed cluster statistics

**Example**:
```json
{
  "nodes": {
    "count": {"total": 3, "data": 3, "master": 1}
  },
  "indices": {
    "count": 15,
    "docs": {"count": 1000000},
    "store": {"size_in_bytes": 5368709120}
  }
}
```

---

#### Alias Operations

##### `list_aliases() -> Dict`
List all aliases in the cluster.

**Returns**: Dictionary of aliases

##### `get_alias(index: str) -> Dict`
Get aliases for a specific index.

**Parameters**:
- `index` (str): Name of the index

**Returns**: Alias information

##### `put_alias(index: str, name: str, body: Dict) -> Dict`
Create or update an alias.

**Parameters**:
- `index` (str): Name of the index
- `name` (str): Alias name
- `body` (dict): Alias configuration (optional filters, routing)

**Example Body**:
```json
{
  "filter": {
    "term": {"user_id": "12345"}
  }
}
```

**⚠️ High-Risk Operation**

##### `delete_alias(index: str, name: str) -> Dict`
Delete an alias.

**Parameters**:
- `index` (str): Name of the index
- `name` (str): Alias name

**⚠️ High-Risk Operation**

---

#### Data Stream Operations

##### `get_data_stream(name: Optional[str] = None) -> Dict`
Get information about data streams.

**Parameters**:
- `name` (str, optional): Name of specific data stream (or all if not provided)

**Returns**: Data stream information

##### `create_data_stream(name: str) -> Dict`
Create a new data stream.

**Parameters**:
- `name` (str): Name of the data stream

**Returns**: Acknowledgement

**⚠️ High-Risk Operation**

##### `delete_data_stream(name: str) -> Dict`
Delete a data stream.

**Parameters**:
- `name` (str): Name of the data stream

**⚠️ High-Risk Operation**

---

#### General Operations

##### `general_api_request(method: str, path: str, params: Optional[Dict] = None, body: Optional[Dict] = None) -> Dict`
Execute an arbitrary API request.

**Parameters**:
- `method` (str): HTTP method (GET, POST, PUT, DELETE, etc.)
- `path` (str): API path (e.g., "/_cat/nodes")
- `params` (dict, optional): Query parameters
- `body` (dict, optional): Request body

**Returns**: API response

**Example**:
```python
general_api_request(
    method="GET",
    path="/_cat/nodes",
    params={"format": "json"}
)
```

**⚠️ High-Risk Operation** - Allows arbitrary API access

---

## Implementation Patterns & Best Practices

### Pattern 1: Thin Tool Wrappers

**Principle**: Tools should be thin wrappers with no business logic.

**Good**:
```python
@mcp.tool()
def create_index(index: str, body: Optional[Dict] = None) -> Dict:
    """Create a new index."""
    return self.search_client.create_index(index=index, body=body)
```

**Bad**:
```python
@mcp.tool()
def create_index(index: str, body: Optional[Dict] = None) -> Dict:
    """Create a new index."""
    # Don't add validation or business logic here
    if not index:
        return {"error": "Index name required"}
    if body and "mappings" not in body:
        body["mappings"] = {}  # Don't modify inputs
    return self.search_client.create_index(index=index, body=body)
```

### Pattern 2: Client Method Reusability

**Principle**: Client methods should be usable outside of MCP tools.

**Implementation**: Keep client methods generic and independent:
```python
class IndexClient(SearchClientBase):
    def create_index(self, index: str, body: Optional[Dict] = None) -> Dict:
        # Usable from anywhere, not just MCP tools
        return self.client.indices.create(index=index, body=body)
```

### Pattern 3: Error Handling at Tool Boundary

**Principle**: Let exceptions bubble up to be caught by the exception handler decorator.

**Good**:
```python
def create_index(self, index: str, body: Optional[Dict] = None) -> Dict:
    return self.client.indices.create(index=index, body=body)
    # Exceptions bubble up to @handle_search_exceptions
```

**Bad**:
```python
def create_index(self, index: str, body: Optional[Dict] = None) -> Dict:
    try:
        return self.client.indices.create(index=index, body=body)
    except Exception as e:
        return {"error": str(e)}  # Don't catch here
```

### Pattern 4: Engine-Agnostic Interfaces

**Principle**: Handle engine differences in client implementation, not in tools.

**Good**:
```python
# In DocumentClient
def index_document(self, index: str, document: Dict, id: Optional[str] = None):
    if self.engine_type == "elasticsearch":
        return self.client.index(index=index, document=document, id=id)
    else:
        return self.client.index(index=index, body=document, id=id)
```

**Bad**:
```python
# In DocumentTools
@mcp.tool()
def index_document(index: str, document: Dict, id: str = None):
    if engine_type == "elasticsearch":  # Don't check in tools
        return self.search_client.es_index_document(...)
    else:
        return self.search_client.os_index_document(...)
```

### Pattern 5: Configuration from Environment

**Principle**: All configuration should come from environment variables, not hardcoded.

**Good**:
```python
hosts = os.environ.get("ELASTICSEARCH_HOSTS", "https://localhost:9200")
```

**Bad**:
```python
hosts = ["https://my-cluster.es.cloud"]  # Don't hardcode
```

---

## Testing & Development

### Local Development Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/thomasxm/CrowdSentinels-AI-MCP.git
   cd crowdsentinel-mcp-server
   ```

2. **Install dependencies**:
   ```bash
   uv sync
   ```

3. **Start Elasticsearch** (Docker):
   ```bash
   docker compose -f docker-compose-elasticsearch.yml up -d
   ```

4. **Configure environment**:
   ```bash
   cp .env.example .env
   # Edit .env with your settings
   ```

5. **Run the server**:
   ```bash
   uv run crowdsentinel-mcp-server
   ```

### Testing with Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "elasticsearch": {
      "command": "uv",
      "args": [
        "--directory",
        "/path/to/crowdsentinel-mcp-server",
        "run",
        "crowdsentinel-mcp-server"
      ],
      "env": {
        "ELASTICSEARCH_HOSTS": "https://localhost:9200",
        "ELASTICSEARCH_USERNAME": "elastic",
        "ELASTICSEARCH_PASSWORD": "changeme",
        "VERIFY_CERTS": "false"
      }
    }
  }
}
```

### Testing with MCP Inspector

```bash
npx @modelcontextprotocol/inspector uv run crowdsentinel-mcp-server
```

### Release Process

1. **Update version**:
   ```bash
   # Update src/version.py
   # Update pyproject.toml
   # Update server.json
   ```

2. **Generate changelog**:
   ```bash
   git cliff --tag vX.Y.Z > CHANGELOG.md
   ```

3. **Create release**:
   ```bash
   make release version=vX.Y.Z
   ```

4. **Publish to PyPI**:
   ```bash
   uv build
   uv publish
   ```

### CI Pipeline

The project has continuous integration that runs on every pull request. The pipeline includes:

- **Automated SAST scanning** using Bandit and Semgrep to catch security issues early
- **Secret detection** via detect-secrets to prevent accidental credential leaks
- **Test suite execution** across Python 3.10, 3.11, 3.12, and 3.13 to ensure broad compatibility
- **Linting and formatting** checks to maintain code quality

All checks must pass before a pull request can be merged.

---

## Troubleshooting

### Common Issues

#### Issue: "Connection refused" error

**Cause**: Elasticsearch/OpenSearch is not running or not accessible

**Solution**:
1. Check if the service is running: `curl https://localhost:9200`
2. Verify `ELASTICSEARCH_HOSTS` environment variable
3. Check firewall rules

#### Issue: "Authentication failed" error

**Cause**: Invalid credentials

**Solution**:
1. Verify `ELASTICSEARCH_API_KEY` or `ELASTICSEARCH_USERNAME`/`ELASTICSEARCH_PASSWORD`
2. Test credentials: `curl -u elastic:changeme https://localhost:9200`
3. Check Elasticsearch user permissions

#### Issue: "SSL verification failed" error

**Cause**: SSL certificate verification issues

**Solution**:
Set `VERIFY_CERTS=false` for development (not recommended for production)

#### Issue: Tools not appearing in MCP client

**Cause**: High-risk operations may be disabled

**Solution**:
1. Check `DISABLE_HIGH_RISK_OPERATIONS` environment variable
2. Check `DISABLE_OPERATIONS` for specific tools
3. Review server logs for registration messages

#### Issue: "Unexpected error: parameter 'basic_auth' is not supported"

**Cause**: Elasticsearch version mismatch

**Solution**:
1. Install `crowdsentinel-mcp-server` and ensure the correct Elasticsearch client library version is installed for your cluster

---

## Performance Considerations

### Request Timeout

Configure timeout to prevent long-running queries:

```bash
REQUEST_TIMEOUT=30  # 30 seconds
```

### Connection Pooling

The official Elasticsearch client uses connection pooling automatically. For high-traffic scenarios:

1. **Increase pool size**: Modify client initialisation in `SearchClientBase`
2. **Use persistent connections**: Already enabled by default
3. **Monitor connection usage**: Add logging in client methods

### Bulk Operations

For indexing multiple documents, consider adding a bulk tool:

```python
@mcp.tool()
def bulk_index_documents(index: str, documents: List[Dict]) -> Dict:
    """Bulk index multiple documents."""
    from elasticsearch.helpers import bulk

    actions = [
        {"_index": index, "_source": doc}
        for doc in documents
    ]

    success, failed = bulk(self.search_client.client, actions)
    return {"success": success, "failed": failed}
```

---

## Future Enhancements

### Potential Features

1. **MCP Resources**: Expose indices/documents as resources
2. **MCP Prompts**: Pre-built search prompt templates
3. **Streaming Search**: Support for scroll API and search_after
4. **Aggregation Builder**: Helper tools for building complex aggregations
5. **Index Template Management**: Tools for managing index templates
6. **Snapshot Management**: Backup and restore operations
7. **Pipeline Management**: Ingest pipeline CRUD operations
8. **Query Validation**: Validate queries before execution
9. **Result Formatting**: Format search results for readability
10. **Multi-Cluster Support**: Connect to multiple clusters simultaneously

### Architecture Improvements

1. **Plugin System**: Load tool classes dynamically from directories
2. **Caching Layer**: Cache frequently accessed data (cluster health, index lists)
3. **Rate Limiting**: Prevent abuse of write operations
4. **Audit Logging**: Log all write operations for compliance
5. **Metrics Collection**: Track tool usage and performance
6. **Configuration Profiles**: Support multiple environment profiles

---

## Conclusion

This CrowdSentinel MCP Server provides a solid foundation for AI-assisted Elasticsearch/OpenSearch interactions. The architecture is designed for:

- **Extensibility**: Easy to add new tools and clients
- **Security**: Risk management and authentication
- **Reliability**: Exception handling and logging
- **Flexibility**: Multiple transport modes and engine support

For questions or contributions, visit the [GitHub repository](https://github.com/thomasxm/CrowdSentinels-AI-MCP).

---

**Document Version**: 2.0
**Last Updated**: 2026-03-15
**Project Version**: 0.3.4
