import os

from dotenv import load_dotenv

from src.clients.common.client import SearchClient
from src.clients.exceptions import handle_search_exceptions

def create_search_client(engine_type: str) -> SearchClient:
    """
    Create a search client for the specified engine type.
    
    Args:
        engine_type: Type of search engine to use ("elasticsearch" or "opensearch")
        
    Returns:
        A search client instance
    """
    # Load configuration from environment variables
    load_dotenv()
    
    # Get configuration from environment variables
    prefix = engine_type.upper()
    hosts_str = os.environ.get(f"{prefix}_HOSTS", "https://localhost:9200")
    hosts = [host.strip() for host in hosts_str.split(",")]
    username = os.environ.get(f"{prefix}_USERNAME")
    password = os.environ.get(f"{prefix}_PASSWORD")
    api_key = os.environ.get(f"{prefix}_API_KEY")
    timeout_str = os.environ.get("REQUEST_TIMEOUT")
    timeout = None
    if timeout_str:
        try:
            timeout = float(timeout_str)
        except ValueError:
            pass  # Invalid value, use default timeout

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
        # Treat as file path to CA certificate
        verify_certs = True
        if not ca_certs:
            ca_certs = verify_raw

    # Elastic Cloud ID (alternative to hosts)
    cloud_id = os.environ.get("ELASTICSEARCH_CLOUD_ID") or os.environ.get("CLOUD_ID")

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
    
    return SearchClient(config, engine_type)

__all__ = [
    'create_search_client',
    'handle_search_exceptions',
    'SearchClient',
]
