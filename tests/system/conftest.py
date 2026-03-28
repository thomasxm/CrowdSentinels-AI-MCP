"""System test fixtures -- real MCP server, real ES, live Shodan.

Delegates to harness/helpers.py for reusable utilities.
See harness/TESTING_GUIDE.md for full documentation.

Run with:
    ELASTICSEARCH_HOSTS=http://localhost:9200 \
    ELASTICSEARCH_USERNAME=elastic \
    ELASTICSEARCH_PASSWORD=<password> \
    VERIFY_CERTS=false \
    uv run pytest tests/system/ -x -v
"""

import pytest
from harness.helpers import (
    ES_HOSTS,
    check_es_reachable,
    create_isolated_storage,
    create_wired_mcp_server,
)

from src.logging_config import get_log_file_path

# Skip entire module if ES is not configured
if not ES_HOSTS:
    pytest.skip("ELASTICSEARCH_HOSTS not set -- skipping system tests", allow_module_level=True)

# Apply 'system' marker to every test in this directory
pytestmark = pytest.mark.system


@pytest.fixture(scope="session")
def _check_es_connectivity():
    """Verify Elasticsearch is reachable before running any system tests."""
    try:
        check_es_reachable()
    except ConnectionError as exc:
        pytest.skip(str(exc))


@pytest.fixture(scope="session")
def _isolate_investigation_storage():
    """Use temporary storage so system tests don't pollute real investigations."""
    return create_isolated_storage()


@pytest.fixture(scope="session")
def mcp_server(_check_es_connectivity, _isolate_investigation_storage):
    """Create a real MCP server connected to real Elasticsearch.

    Session-scoped -- created once and shared across all system tests.
    Investigation singletons are wired together so the full pipeline
    (create -> enrich -> export) works through MCP.
    """
    return create_wired_mcp_server()


@pytest.fixture(scope="session")
def log_file_path():
    """Return the MCP server log file path."""
    return get_log_file_path()


@pytest.fixture(autouse=True)
def capture_mcp_logs(request, log_file_path):
    """Capture MCP server logs during each test.

    Autouse -- runs on EVERY system test, no opt-out.

    - Records log file position before the test
    - After test, reads new log lines
    - FORCES test failure if any '!!! FAIL:' lines appear
      (unless test is marked @pytest.mark.expects_tool_failure)
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

    # FORCE failure if tool errors occurred but test assertions passed
    # Unless the test is marked with @pytest.mark.expects_tool_failure
    expects_failure = request.node.get_closest_marker("expects_tool_failure")
    if fail_lines and not expects_failure:
        pytest.fail(f"MCP tool failure detected in server logs during '{request.node.name}':\n" + "\n".join(fail_lines))
