"""Reusable utility functions for system tests.

These are pure functions with no pytest dependency. The pytest fixtures
in tests/system/conftest.py delegate to these helpers.
"""

import os
import tempfile
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Environment variable constants
# ---------------------------------------------------------------------------

ES_HOSTS = os.environ.get("ELASTICSEARCH_HOSTS", "")
ES_USERNAME = os.environ.get("ELASTICSEARCH_USERNAME", "")
ES_PASSWORD = os.environ.get("ELASTICSEARCH_PASSWORD", "")
VERIFY_CERTS = os.environ.get("VERIFY_CERTS", "true")


# ---------------------------------------------------------------------------
# Elasticsearch connectivity
# ---------------------------------------------------------------------------


def check_es_reachable(
    hosts: str | None = None,
    username: str | None = None,
    password: str | None = None,
) -> None:
    """Verify Elasticsearch is reachable. Raises on failure.

    Args:
        hosts: ES host URL (defaults to ELASTICSEARCH_HOSTS env var)
        username: ES username (defaults to ELASTICSEARCH_USERNAME env var)
        password: ES password (defaults to ELASTICSEARCH_PASSWORD env var)

    Raises:
        ConnectionError: If ES is not reachable
    """
    import httpx

    h = hosts or ES_HOSTS or "http://localhost:9200"
    u = username or ES_USERNAME
    p = password or ES_PASSWORD

    auth = (u, p) if u else None
    try:
        resp = httpx.get(h, auth=auth, verify=False, timeout=5)
        resp.raise_for_status()
    except Exception as exc:
        raise ConnectionError(f"Elasticsearch not reachable at {h}: {exc}") from exc


# ---------------------------------------------------------------------------
# Isolated storage
# ---------------------------------------------------------------------------


def create_isolated_storage(
    prefix: str = "crowdsentinel-system-test-",
) -> Any:
    """Create a temporary StorageConfig for test isolation.

    Returns a StorageConfig rooted in a temp directory so system tests
    do not pollute real investigation data.
    """
    from src.storage.config import StorageConfig, set_config

    tmp = tempfile.mkdtemp(prefix=prefix)
    cfg = StorageConfig(base_path=Path(tmp) / ".crowdsentinel")
    set_config(cfg)
    return cfg


# ---------------------------------------------------------------------------
# MCP server with wired singletons
# ---------------------------------------------------------------------------


def create_wired_mcp_server(engine_type: str = "elasticsearch") -> Any:
    """Create a real MCP server and wire investigation singletons.

    The CrowdSentinel server has two investigation state singletons:
    - ``investigation_state_tools._investigation_client`` (used by create_investigation)
    - ``auto_capture._client`` (used by enrich_iocs, wireshark tools)

    This function wires them to the same instance so the full pipeline
    (create -> enrich -> export) works through MCP.

    Returns:
        The FastMCP server instance (``server.mcp``)
    """
    from src.logging_config import configure_logging
    from src.server import SearchMCPServer

    configure_logging("crowdsentinel")
    server = SearchMCPServer(engine_type)

    # Wire singletons
    import src.storage.auto_capture as ac
    import src.tools.investigation_state_tools as ist

    shared_client = ist.get_investigation_client()
    ac._client = shared_client

    return server.mcp
