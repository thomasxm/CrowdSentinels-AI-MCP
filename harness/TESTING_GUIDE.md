# CrowdSentinel Testing Guide

## The Three-Layer Testing Pyramid

```
                  /\
                 /  \   Eval Harness (future)
                /    \   Multi-tool chains via Claude against real ES
               /------\   Trigger: manual
              /        \
             /  System  \  21 system tests
            /   Tests    \  FastMCP Client -> real MCP protocol -> real ES + live Shodan
           /              \  Log capture forces failure on hidden tool errors
          /----------------\  Trigger: pre-commit or manual
         /                  \
        /    Unit Tests      \  509+ unit tests
       /     (mocked)         \  Direct function calls, mocked HTTP
      /------------------------\  Trigger: pre-commit + CI
```

### Layer 1: Unit Tests (509+ tests)

- **Location:** `tests/` (everything except `tests/system/`)
- **Data:** Mocked HTTP responses, fixture files in `tests/fixtures/`
- **Infrastructure:** None required
- **Speed:** ~28 seconds
- **Run:** `uv run pytest tests/ -m "not system" -q`

### Layer 2: System Tests (21 tests)

- **Location:** `tests/system/`
- **Data:** Real Elasticsearch (37K winlogbeat + 105K SSH events) + live Shodan InternetDB
- **Infrastructure:** ES running, internet access
- **Speed:** ~4 seconds
- **Run:** `uv run pytest tests/system/ -x -v` (with ES env vars set)

### Layer 3: Eval Harness (future)

- **Location:** `.claude/evals/` (planned)
- **Data:** Real ES with known APT data
- **What it tests:** Multi-tool chains orchestrated by Claude
- **Trigger:** Manual or weekly CI

---

## How Log Capture Works

The `capture_mcp_logs` fixture in `tests/system/conftest.py` is **autouse** — it runs on every system test with no opt-out.

### Mechanism

1. **Before test:** Records the byte offset of `mcp-server.log`
2. **Test runs:** MCP tool calls are logged by `handle_search_exceptions`:
   - `>>> CALL: tool_name | params` — tool invoked
   - `<<< DONE: tool_name | 1.2s | hits=50` — tool succeeded
   - `!!! FAIL: tool_name | ValueError: ...` — tool threw exception
3. **After test:** Reads new lines since the recorded offset
4. **Scans for `!!! FAIL:`:** If found and the test is NOT marked `@expects_tool_failure`, the test is **force-failed** via `pytest.fail()`

### Why This Matters

The `handle_search_exceptions` decorator in `src/clients/exceptions.py` catches all exceptions and returns `TextContent("Unexpected error...")` to the MCP client. A unit test calling the internal `_method()` directly never sees this — the exception propagates normally. But through the real MCP protocol, the error is silently swallowed.

The log capture fixture catches these invisible failures because the decorator always logs `!!! FAIL:` before returning the error.

### Example

```
Test: test_full_investigation_pipeline
  MCP log: >>> CALL: enrich_iocs | providers=['shodan_internetdb']
  MCP log: <<< DONE: enrich_iocs | 0.8s | enriched=3
  Assertion: passes (result contains "enriched")
  Log scan: no !!! FAIL: lines
  Result: PASS

Test: test_broken_tool (hypothetical)
  MCP log: >>> CALL: broken_tool | arg=value
  MCP log: !!! FAIL: broken_tool | 0.01s | TypeError: missing argument
  Assertion: passes (TextContent contains "error" — test expected this)
  Log scan: FOUND !!! FAIL: — NOT marked @expects_tool_failure
  Result: FORCED FAIL  <-- the harness caught an invisible error
```

---

## The `@expects_tool_failure` Marker

Some tests deliberately provoke errors — querying a nonexistent index, exporting in an unsupported format, calling a tool without required configuration. These tests expect `!!! FAIL:` in the logs.

Mark them to suppress the log scanner:

```python
@pytest.mark.asyncio
@pytest.mark.expects_tool_failure
async def test_search_nonexistent_index(mcp_server):
    async with Client(mcp_server) as client:
        result = await client.call_tool(
            "search_documents",
            {"index": "nonexistent-xyz", "body": {"query": {"match_all": {}}}},
        )
        assert "error" in str(result).lower()
```

Without this marker, the log scanner would force-fail the test even though the assertion passed.

---

## How the MCP Server Fixture Works

The `mcp_server` fixture is **session-scoped** — created once, shared across all 21 system tests.

### What It Does

1. **Checks ES connectivity** via `harness.helpers.check_es_reachable()`
2. **Creates isolated storage** in a temp directory via `harness.helpers.create_isolated_storage()` — system tests never touch real investigation data
3. **Creates the real MCP server** via `harness.helpers.create_wired_mcp_server()`:
   - Instantiates `SearchMCPServer("elasticsearch")` — loads 6,061 detection rules, registers 102 tools
   - **Wires the two investigation singletons** together: `investigation_state_tools._investigation_client` and `auto_capture._client` point to the same `InvestigationStateClient` so that `create_investigation` and `enrich_iocs` share state

### Why Singleton Wiring Matters

CrowdSentinel has two global `InvestigationStateClient` singletons:
- `src/tools/investigation_state_tools.py:_investigation_client` — used by `create_investigation`, `close_investigation`, `export_iocs`
- `src/storage/auto_capture.py:_client` — used by `enrich_iocs`, `auto_capture_*_results()`

Without wiring, creating an investigation via MCP then calling `enrich_iocs` would fail with "No investigation found" because they use different client instances. The harness wires them to the same object.

---

## How to Add a System Test for a New Tool

### Step 1: Choose the Right Test File

| If your tool is... | Add to... |
|---|---|
| An ES query tool | `test_es_via_mcp.py` |
| An enrichment/TI tool | `test_enrichment_pipeline.py` |
| A tool that should degrade gracefully | `test_degradation.py` |
| Something new (PCAP, Chainsaw, etc.) | Create `test_<category>.py` |

### Step 2: Write the Test

```python
@pytest.mark.asyncio
async def test_my_new_tool(mcp_server):
    """Describe what this tests in one line."""
    async with Client(mcp_server) as client:
        result = await client.call_tool(
            "my_new_tool",
            {"param1": "value1", "param2": 42},
        )
        text = str(result)
        assert "expected_content" in text
```

### Step 3: Run It

```bash
ELASTICSEARCH_HOSTS=http://localhost:9200 \
ELASTICSEARCH_USERNAME=elastic \
ELASTICSEARCH_PASSWORD=your_password \
VERIFY_CERTS=false \
uv run pytest tests/system/test_my_file.py::test_my_new_tool -v
```

### Step 4: If Your Test Deliberately Provokes an Error

Add `@pytest.mark.expects_tool_failure`:

```python
@pytest.mark.asyncio
@pytest.mark.expects_tool_failure
async def test_my_tool_bad_input(mcp_server):
    ...
```

---

## Graceful Skip Mechanism

The `tests/system/conftest.py` module checks `ELASTICSEARCH_HOSTS` at import time:

```python
ES_HOSTS = os.environ.get("ELASTICSEARCH_HOSTS", "")
if not ES_HOSTS:
    pytest.skip("ELASTICSEARCH_HOSTS not set — skipping system tests", allow_module_level=True)
```

This means:
- **CI** (where ES vars are not set) — system tests skip automatically, no failures
- **Local dev** (with ES running) — system tests run normally
- **`pytest tests/`** — runs everything; system tests skip if ES not configured

---

## Marker Reference

| Marker | Registered | Purpose |
|--------|-----------|---------|
| `system` | Yes (`pyproject.toml`) | Applied to all `tests/system/` tests via `pytestmark`. Run with `-m system` or exclude with `-m "not system"` |
| `expects_tool_failure` | Yes (`pyproject.toml`) | Suppress log-capture forced failure for tests that deliberately trigger tool errors |
| `asyncio` | Yes (pytest-asyncio) | Required on all async test functions |

---

## Harness Module Structure

```
harness/
  __init__.py          Package marker
  helpers.py           Pure utility functions (no pytest dependency):
                         - check_es_reachable()
                         - create_isolated_storage()
                         - create_wired_mcp_server()
                         - ES_HOSTS, ES_USERNAME, ES_PASSWORD constants
  README.md            Quick start and file map
  TESTING_GUIDE.md     This file
```

The `helpers.py` functions are called by the pytest fixtures in `tests/system/conftest.py`. They are deliberately separated so they can be imported and used outside of pytest (e.g., in scripts, notebooks, or future eval harness tooling).
