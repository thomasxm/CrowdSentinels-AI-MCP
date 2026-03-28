"""System test fixtures — real MCP server, real ES, live Shodan.

These tests exercise the full MCP protocol path (tool registration,
handle_search_exceptions decorator, JSON-RPC serialisation) against
real infrastructure. They are NOT mocked.

Prerequisites:
    - Elasticsearch running on ELASTICSEARCH_HOSTS (default: http://localhost:9200)
    - ELASTICSEARCH_USERNAME / ELASTICSEARCH_PASSWORD set
    - Internet access for Shodan InternetDB (no key needed)

Run with:
    ELASTICSEARCH_HOSTS=http://localhost:9200 \\
    ELASTICSEARCH_USERNAME=elastic \\
    ELASTICSEARCH_PASSWORD=vJqz2wDD \\
    VERIFY_CERTS=false \\
    uv run pytest tests/system/ -x -v
"""

import os
import tempfile
from pathlib import Path

import pytest

# Skip entire module if ES is not configured
ES_HOSTS = os.environ.get("ELASTICSEARCH_HOSTS", "")
if not ES_HOSTS:
    pytest.skip("ELASTICSEARCH_HOSTS not set — skipping system tests", allow_module_level=True)


@pytest.fixture(scope="session")
def _check_es_connectivity():
    """Verify Elasticsearch is reachable before running any system tests."""
    import httpx

    hosts = os.environ.get("ELASTICSEARCH_HOSTS", "http://localhost:9200")
    username = os.environ.get("ELASTICSEARCH_USERNAME", "")
    password = os.environ.get("ELASTICSEARCH_PASSWORD", "")

    try:
        auth = (username, password) if username else None
        resp = httpx.get(hosts, auth=auth, verify=False, timeout=5)
        resp.raise_for_status()
    except Exception as exc:
        pytest.skip(f"Elasticsearch not reachable at {hosts}: {exc}")


@pytest.fixture(scope="session")
def _isolate_investigation_storage():
    """Use temporary storage so system tests don't pollute real investigations."""
    from src.storage.config import StorageConfig, set_config

    tmp = tempfile.mkdtemp(prefix="crowdsentinel-system-test-")
    cfg = StorageConfig(base_path=Path(tmp) / ".crowdsentinel")
    set_config(cfg)
    return cfg


@pytest.fixture(scope="session")
def mcp_server(_check_es_connectivity, _isolate_investigation_storage):
    """Create a real MCP server connected to real Elasticsearch.

    This is a session-scoped fixture — the server is created once and
    shared across all system tests. This mirrors how the server runs
    in production (single process, many tool calls).

    Also wires the two investigation state singletons together so that
    create_investigation (investigation_state_tools) and enrich_iocs
    (auto_capture) share the same client.
    """
    from src.logging_config import configure_logging
    from src.server import SearchMCPServer

    configure_logging("crowdsentinel")
    server = SearchMCPServer("elasticsearch")

    # Wire the two investigation singletons to the same client instance
    import src.storage.auto_capture as ac
    import src.tools.investigation_state_tools as ist

    shared_client = ist.get_investigation_client()
    ac._client = shared_client

    return server.mcp


@pytest.fixture(scope="session")
def log_file_path():
    """Return the MCP server log file path."""
    from src.logging_config import get_log_file_path

    return get_log_file_path()


@pytest.fixture(autouse=True)
def capture_mcp_logs(request, log_file_path):
    """Capture MCP server logs during each test.

    This fixture is autouse — it runs on EVERY system test, no opt-out.

    Behaviour:
        - Records log file position before the test
        - After test, reads new log lines
        - FORCES test failure if any '!!! FAIL:' lines appear in logs
        - On any test failure, prints the log excerpt for debugging
    """
    start_pos = 0
    if log_file_path.exists():
        start_pos = log_file_path.stat().st_size

    yield

    if not log_file_path.exists():
        return

    with open(log_file_path) as f:
        f.seek(start_pos)
        new_logs = f.read()

    if not new_logs:
        return

    # Scan for tool failures invisible to the test assertions
    fail_lines = [line for line in new_logs.splitlines() if "!!! FAIL:" in line]
    error_lines = [line for line in new_logs.splitlines() if "| ERROR" in line]

    # FORCE failure if tool errors occurred but test assertions passed
    # Unless the test is marked with @pytest.mark.expects_tool_failure
    expects_failure = request.node.get_closest_marker("expects_tool_failure")
    if fail_lines and not expects_failure:
        pytest.fail(f"MCP tool failure detected in server logs during '{request.node.name}':\n" + "\n".join(fail_lines))
