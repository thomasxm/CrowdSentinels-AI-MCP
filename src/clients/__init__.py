import logging
import os

from dotenv import load_dotenv

from src.clients.common.client import SearchClient
from src.clients.exceptions import handle_search_exceptions

_logger = logging.getLogger("crowdsentinel.clients")


class ConfigurationError(Exception):
    """Raised when required configuration is missing."""


def _build_config(engine_type: str):
    """Build client configuration from environment variables.

    All connection parameters are user-configurable via environment variables.
    Defaults to https://localhost:9200 for local/CI testing. Users configure
    their target via ELASTICSEARCH_HOSTS or ELASTICSEARCH_CLOUD_ID.

    Returns:
        config dict
    """
    load_dotenv()

    prefix = engine_type.upper()
    hosts_env = os.environ.get(f"{prefix}_HOSTS")
    cloud_id = os.environ.get("ELASTICSEARCH_CLOUD_ID") or os.environ.get("CLOUD_ID")

    # Default to https://localhost:9200 when nothing is configured.
    # Users can override via env vars for any environment:
    #   Local HTTP:    export ELASTICSEARCH_HOSTS="http://localhost:9200"
    #   Remote HTTPS:  export ELASTICSEARCH_HOSTS="https://my-es-server:9200"
    #   Multi-node:    export ELASTICSEARCH_HOSTS="https://node1:9200,https://node2:9200"
    #   Elastic Cloud: export ELASTICSEARCH_CLOUD_ID="deployment:base64..."
    default_host = "https://localhost:9200"
    hosts_str = hosts_env or default_host
    hosts = [h.strip() for h in hosts_str.split(",")]

    if not hosts_env and not cloud_id:
        _logger.info(
            "%s_HOSTS not set, using default: %s. "
            "Configure via: export %s_HOSTS=\"http(s)://your-host:9200\"",
            prefix, default_host, prefix,
        )
    username = os.environ.get(f"{prefix}_USERNAME")
    password = os.environ.get(f"{prefix}_PASSWORD")
    api_key = os.environ.get(f"{prefix}_API_KEY")
    timeout_str = os.environ.get("REQUEST_TIMEOUT")
    timeout = None
    if timeout_str:
        try:
            timeout = float(timeout_str)
        except ValueError:
            pass

    # TLS / certificate configuration
    ca_certs = os.environ.get("ELASTICSEARCH_CA_CERT") or os.environ.get("CA_CERT")
    client_cert = os.environ.get("ELASTICSEARCH_CLIENT_CERT") or os.environ.get("CLIENT_CERT")
    client_key = os.environ.get("ELASTICSEARCH_CLIENT_KEY") or os.environ.get("CLIENT_KEY")

    # VERIFY_CERTS: "true" = system CA bundle, "false" = skip, path = custom CA
    verify_raw = os.environ.get("VERIFY_CERTS", "false").strip()
    if verify_raw.lower() == "true":
        verify_certs = True
    elif verify_raw.lower() == "false":
        verify_certs = False
    else:
        verify_certs = True
        if not ca_certs:
            ca_certs = verify_raw

    # Bearer token auth (service tokens, etc.)
    bearer_token = os.environ.get("ELASTICSEARCH_BEARER_TOKEN") or os.environ.get("BEARER_TOKEN")

    config = {
        "hosts": hosts,
        "username": username,
        "password": password,
        "api_key": api_key,
        "verify_certs": verify_certs,
        "timeout": timeout,
        "ca_certs": ca_certs,
        "client_cert": client_cert,
        "client_key": client_key,
        "cloud_id": cloud_id,
        "bearer_token": bearer_token,
    }

    return config


def create_search_client(engine_type: str) -> SearchClient:
    """
    Create a search client for the specified engine type.

    All connection settings are configurable via environment variables.
    Defaults to https://localhost:9200 for easy local/CI testing.

    When using the default host (user hasn't set HOSTS), if HTTPS fails
    with a TLS error the client automatically retries with HTTP — so both
    TLS and non-TLS local setups work out of the box.

    When the user explicitly configures HOSTS, that value is respected
    exactly with no fallback.

    Supported environments:
        Local dev (no TLS):  ELASTICSEARCH_HOSTS=http://localhost:9200
        Local dev (TLS):     ELASTICSEARCH_HOSTS=https://localhost:9200
        Remote / staging:    ELASTICSEARCH_HOSTS=https://es.staging.example.com:9200
        Production:          ELASTICSEARCH_HOSTS=https://es.prod.example.com:9200 + VERIFY_CERTS=true
        Elastic Cloud:       ELASTICSEARCH_CLOUD_ID=deployment:base64...
        Multi-node:          ELASTICSEARCH_HOSTS=https://node1:9200,https://node2:9200

    Args:
        engine_type: Type of search engine to use ("elasticsearch" or "opensearch")

    Returns:
        A search client instance
    """
    config = _build_config(engine_type)

    prefix = engine_type.upper()
    user_set_hosts = os.environ.get(f"{prefix}_HOSTS") is not None

    try:
        client = SearchClient(config, engine_type)
        # Lightweight connectivity check — use short timeout and no retries
        # so TLS failures are detected quickly rather than retrying 3 times.
        client.client.info(request_timeout=5)
        return client
    except Exception as exc:
        exc_msg = str(exc)
        is_ssl_error = any(
            s in exc_msg
            for s in ("SSL", "TLS", "CERTIFICATE_VERIFY", "RECORD_LAYER")
        )

        if not is_ssl_error or user_set_hosts:
            # User explicitly configured hosts — respect their choice,
            # or it's a non-TLS error. Let it propagate.
            raise

        # Default host failed with TLS error — try HTTP fallback for local dev
        http_hosts = [
            h.replace("https://", "http://", 1) for h in config["hosts"]
        ]
        _logger.info(
            "Default HTTPS failed (TLS error), retrying with HTTP: %s",
            http_hosts,
        )
        config["hosts"] = http_hosts
        config["verify_certs"] = False

        client = SearchClient(config, engine_type)
        client.client.info()
        _logger.info(
            "Connected via HTTP. To make this permanent: "
            "export %s_HOSTS=\"%s\"",
            prefix, ",".join(http_hosts),
        )
        return client

__all__ = [
    'create_search_client',
    'handle_search_exceptions',
    'SearchClient',
]
