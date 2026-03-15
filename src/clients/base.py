import logging
import warnings
from abc import ABC

import httpx
from elasticsearch import Elasticsearch
from opensearchpy import OpenSearch


class SearchClientBase(ABC):
    def __init__(self, config: dict, engine_type: str):
        """
        Initialize the search client.
        
        Args:
            config: Configuration dictionary with connection parameters
            engine_type: Type of search engine to use ("elasticsearch" or "opensearch")
        """
        self.logger = logging.getLogger()
        self.config = config
        self.engine_type = engine_type

        # Extract common configuration
        hosts = config.get("hosts")
        username = config.get("username")
        password = config.get("password")
        api_key = config.get("api_key")
        verify_certs = config.get("verify_certs", False)
        timeout = config.get("timeout")
        ca_certs = config.get("ca_certs")
        client_cert = config.get("client_cert")
        client_key = config.get("client_key")
        cloud_id = config.get("cloud_id")
        bearer_token = config.get("bearer_token")

        # Disable insecure request warnings if verify_certs is False
        if not verify_certs:
            warnings.filterwarnings("ignore", message=".*verify_certs=False is insecure.*")
            warnings.filterwarnings("ignore", message=".*Unverified HTTPS request is being made to host.*")

            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except ImportError:
                pass

        # Initialize client based on engine type
        if engine_type == "elasticsearch":
            # Get auth parameters based on elasticsearch package version and authentication method
            auth_params = self._get_elasticsearch_auth_params(
                username, password, api_key, bearer_token,
            )

            es_kwargs = {
                "verify_certs": verify_certs,
                **auth_params
            }

            # Cloud ID takes precedence over hosts
            if cloud_id:
                es_kwargs["cloud_id"] = cloud_id
                self.logger.info("Elasticsearch client using Cloud ID")
            else:
                es_kwargs["hosts"] = hosts

            # TLS certificate configuration
            if ca_certs:
                es_kwargs["ca_certs"] = ca_certs
            if client_cert:
                es_kwargs["client_cert"] = client_cert
            if client_key:
                es_kwargs["client_key"] = client_key

            if timeout is not None:
                es_kwargs["request_timeout"] = timeout
            self.client = Elasticsearch(**es_kwargs)
            self.logger.info(f"Elasticsearch client initialised with hosts: {cloud_id or hosts}")
        elif engine_type == "opensearch":
            os_kwargs = {
                "hosts": hosts,
                "http_auth": (username, password) if username and password else None,
                "verify_certs": verify_certs
            }
            if ca_certs:
                os_kwargs["ca_certs"] = ca_certs
            if client_cert:
                os_kwargs["client_cert"] = client_cert
            if client_key:
                os_kwargs["client_key"] = client_key
            if timeout is not None:
                os_kwargs["timeout"] = timeout
            self.client = OpenSearch(**os_kwargs)
            self.logger.info(f"OpenSearch client initialised with hosts: {hosts}")
        else:
            raise ValueError(f"Unsupported engine type: {engine_type}")

        # General REST client
        base_url = hosts[0] if isinstance(hosts, list) else hosts
        self.general_client = GeneralRestClient(
            base_url=base_url,
            username=username,
            password=password,
            api_key=api_key,
            bearer_token=bearer_token,
            verify_certs=verify_certs,
            ca_certs=ca_certs,
            client_cert=client_cert,
            client_key=client_key,
            timeout=timeout,
        )

    def _get_elasticsearch_auth_params(
        self,
        username: str | None,
        password: str | None,
        api_key: str | None,
        bearer_token: str | None = None,
    ) -> dict:
        """
        Get authentication parameters for Elasticsearch client based on package version.

        Priority: bearer_token > api_key > username/password

        Args:
            username: Username for authentication
            password: Password for authentication
            api_key: API key for authentication
            bearer_token: Bearer/service token for authentication

        Returns:
            Dictionary with appropriate auth parameters for the ES version
        """
        # Bearer token takes highest precedence
        if bearer_token:
            return {"bearer_auth": bearer_token}

        # API key takes precedence over username/password
        if api_key:
            return {"api_key": api_key}

        if not username or not password:
            return {}

        # Check Elasticsearch package version to determine auth parameter name
        try:
            from elasticsearch import __version__ as es_version
            # Convert version tuple to string format
            version_str = '.'.join(map(str, es_version))
            self.logger.info(f"Elasticsearch client version: {version_str}")
            major_version = es_version[0]
            if major_version >= 8:
                # ES 8+ uses basic_auth
                return {"basic_auth": (username, password)}
            # ES 7 and below use http_auth
            return {"http_auth": (username, password)}
        except Exception as e:
            self.logger.error(f"Failed to detect Elasticsearch version: {e}")
            # If we can't detect version, try basic_auth first (ES 8+ default)
            return {"basic_auth": (username, password)}

class GeneralRestClient:
    def __init__(
        self,
        base_url: str | None,
        username: str | None,
        password: str | None,
        api_key: str | None,
        verify_certs: bool,
        timeout: float | None = None,
        bearer_token: str | None = None,
        ca_certs: str | None = None,
        client_cert: str | None = None,
        client_key: str | None = None,
    ):
        self.base_url = base_url.rstrip("/") if base_url else ""
        self.auth = (username, password) if username and password else None
        self.api_key = api_key
        self.bearer_token = bearer_token
        self.verify_certs = verify_certs
        self.ca_certs = ca_certs
        self.client_cert = client_cert
        self.client_key = client_key
        self.timeout = timeout

    def request(self, method, path, params=None, body=None):
        url = f"{self.base_url}/{path.lstrip('/')}"
        headers = {}

        # Auth header priority: bearer token > API key > basic auth
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        elif self.api_key:
            headers["Authorization"] = f"ApiKey {self.api_key}"

        # TLS configuration: CA cert path or boolean
        verify = self.ca_certs if self.ca_certs else self.verify_certs
        client_kwargs = {"verify": verify}
        if self.client_cert and self.client_key:
            client_kwargs["cert"] = (self.client_cert, self.client_key)
        elif self.client_cert:
            client_kwargs["cert"] = self.client_cert
        if self.timeout is not None:
            client_kwargs["timeout"] = self.timeout
        with httpx.Client(**client_kwargs) as client:
            resp = client.request(
                method=method.upper(),
                url=url,
                params=params,
                json=body,
                auth=self.auth if not (self.api_key or self.bearer_token) else None,
                headers=headers
            )
            resp.raise_for_status()
            ct = resp.headers.get("content-type", "")
            if ct.startswith("application/json"):
                return resp.json()
            return resp.text
