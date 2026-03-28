# CrowdSentinel Development Harness

## What Is the Harness?

The harness is CrowdSentinel's system test infrastructure. It provides shared utilities, fixtures, and documentation for tests that exercise the **full MCP protocol path** against real Elasticsearch, live Shodan, and real investigation state. These are not mocked.

When a developer adds a new MCP tool, the harness ensures it works end-to-end — not just that the internal function returns the right dict, but that a real MCP client can call it, real data flows through, and any server-side errors are caught even if the return value looks correct.

## Prerequisites

| Requirement | How to Set Up |
|---|---|
| Elasticsearch running | `docker-compose -f docker-compose-elasticsearch.yml up -d` |
| ES credentials | Set env vars (see below) |
| Internet access | Required for Shodan InternetDB (free, no key needed) |

### Environment Variables

```bash
export ELASTICSEARCH_HOSTS="http://localhost:9200"
export ELASTICSEARCH_USERNAME="elastic"
export ELASTICSEARCH_PASSWORD="your_password"
export VERIFY_CERTS="false"
```

If `ELASTICSEARCH_HOSTS` is not set, all system tests **skip gracefully** — no failures.

## Quick Start

```bash
# Run system tests only (requires ES + internet)
ELASTICSEARCH_HOSTS=http://localhost:9200 \
ELASTICSEARCH_USERNAME=elastic \
ELASTICSEARCH_PASSWORD=vJqz2wDD \
VERIFY_CERTS=false \
uv run pytest tests/system/ -x -v

# Run unit tests only (no infrastructure needed)
uv run pytest tests/ -m "not system" -q

# Run everything (system tests auto-skip if ES not available)
uv run pytest tests/ -q --ignore=tests/test_live_elasticsearch_integration.py
```

## File Map

| File | Purpose |
|------|---------|
| `harness/__init__.py` | Package marker |
| `harness/helpers.py` | Reusable utilities: ES check, isolated storage, MCP server creation |
| `harness/README.md` | This file |
| `harness/TESTING_GUIDE.md` | Comprehensive guide: pyramid, log capture, adding tests |
| `tests/system/conftest.py` | Pytest fixtures (delegates to `harness/helpers.py`) |
| `tests/system/test_tool_registration.py` | MCP tool registration validation (4 tests) |
| `tests/system/test_es_via_mcp.py` | Real ES queries via MCP protocol (5 tests) |
| `tests/system/test_enrichment_pipeline.py` | Full enrichment pipeline with live Shodan (6 tests) |
| `tests/system/test_degradation.py` | Graceful error handling (6 tests) |

## Further Reading

See [TESTING_GUIDE.md](TESTING_GUIDE.md) for the full testing architecture, how log capture works, and how to add system tests for new tools.
