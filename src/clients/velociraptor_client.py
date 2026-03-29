"""Velociraptor gRPC client for forensic artifact collection.

Provides a class-based interface to the Velociraptor API, with lazy connection
initialization, input sanitization, and async-safe wrappers for use in
FastMCP's async context.
"""

import asyncio
import json
import logging
import re
from typing import Any

logger = logging.getLogger(__name__)

# Lazy imports — pyvelociraptor and grpc are optional dependencies
_grpc = None
_api_pb2 = None
_api_pb2_grpc = None
_yaml = None


def _ensure_imports() -> None:
    """Import optional dependencies on first use."""
    global _grpc, _api_pb2, _api_pb2_grpc, _yaml
    if _grpc is not None:
        return
    try:
        import grpc as grpc_mod
        import yaml as yaml_mod
        from pyvelociraptor import api_pb2 as pb2
        from pyvelociraptor import api_pb2_grpc as pb2_grpc

        _grpc = grpc_mod
        _api_pb2 = pb2
        _api_pb2_grpc = pb2_grpc
        _yaml = yaml_mod
    except ImportError as e:
        raise ImportError(
            "Velociraptor dependencies not installed. "
            "Install with: pip install crowdsentinel-mcp-server[velociraptor]"
        ) from e


# Regex for sanitizing VQL string parameters
_SAFE_HOSTNAME_RE = re.compile(r"^[\w.\-]+$")
_SAFE_REGEX_RE = re.compile(r"^[\w.\-\s*+?^${}()|\\[\]/,:=]+$")
_SAFE_ARTIFACT_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._\-/]*$")
_SAFE_FLOW_ID_RE = re.compile(r"^F\.[A-Za-z0-9]+$")
_SAFE_RESULT_SCOPE_RE = re.compile(r"^(/[A-Za-z][A-Za-z0-9_]*)?$")


def _sanitize_hostname(value: str) -> str:
    """Sanitize a hostname for safe inclusion in VQL queries."""
    if not _SAFE_HOSTNAME_RE.match(value):
        raise ValueError(f"Invalid hostname characters: {value!r}")
    return value


def _sanitize_regex(value: str) -> str:
    """Sanitize a regex parameter for safe inclusion in VQL queries.

    Rejects single-quotes to prevent VQL string escape.
    """
    if not _SAFE_REGEX_RE.match(value):
        raise ValueError(f"Invalid regex characters: {value!r}")
    return value


def _sanitize_client_id(value: str) -> str:
    """Sanitize a Velociraptor client ID (format: C.xxxx)."""
    if not re.match(r"^C\.[a-f0-9]+$", value):
        raise ValueError(f"Invalid client_id format: {value!r}")
    return value


def _sanitize_fields(value: str) -> str:
    """Sanitize a fields parameter (comma-separated field names or '*')."""
    value = value.strip()
    if value == "*":
        return value
    # Allow field names with dots, underscores, and commas
    if not re.match(r"^[\w.,\s*]+$", value):
        raise ValueError(f"Invalid fields parameter: {value!r}")
    return value


def _sanitize_artifact(value: str) -> str:
    """Sanitize an artifact name (e.g. Windows.System.Pslist)."""
    if not _SAFE_ARTIFACT_RE.match(value):
        raise ValueError(f"Invalid artifact name: {value!r}")
    return value


def _sanitize_flow_id(value: str) -> str:
    """Sanitize a Velociraptor flow ID (format: F.xxxx)."""
    if not _SAFE_FLOW_ID_RE.match(value):
        raise ValueError(f"Invalid flow_id format: {value!r}")
    return value


def _sanitize_result_scope(value: str) -> str:
    """Sanitize a result scope (empty or /AnalysisName)."""
    if not _SAFE_RESULT_SCOPE_RE.match(value):
        raise ValueError(f"Invalid result_scope: {value!r}")
    return value


def _sanitize_drive(value: str) -> str:
    """Sanitize a drive letter (e.g. C:)."""
    if not re.match(r"^[A-Za-z]:$", value):
        raise ValueError(f"Invalid drive letter: {value!r}")
    return value


def _sanitize_date(value: str) -> str:
    """Sanitize a date parameter (empty or ISO-8601-like)."""
    if not value:
        return value
    if not re.match(r"^[\d\-T:Z.+]+$", value):
        raise ValueError(f"Invalid date format: {value!r}")
    return value


class VelociraptorClient:
    """Client for Velociraptor gRPC API with lazy initialization."""

    def __init__(self, config_path: str):
        """
        Initialize the client with a config path.

        The gRPC connection is established lazily on first use.

        Args:
            config_path: Path to the Velociraptor api_client.yaml file
        """
        self._config_path = config_path
        self._stub = None
        self._config: dict[str, Any] | None = None

    def _ensure_connected(self) -> None:
        """Establish gRPC connection if not already connected."""
        if self._stub is not None:
            return

        _ensure_imports()

        with open(self._config_path) as f:
            self._config = _yaml.safe_load(f)

        creds = _grpc.ssl_channel_credentials(
            root_certificates=self._config["ca_certificate"].encode("utf-8"),
            private_key=self._config["client_private_key"].encode("utf-8"),
            certificate_chain=self._config["client_cert"].encode("utf-8"),
        )
        channel_opts = (("grpc.ssl_target_name_override", "VelociraptorServer"),)
        channel = _grpc.secure_channel(
            self._config["api_connection_string"], creds, options=channel_opts
        )
        self._stub = _api_pb2_grpc.APIStub(channel)
        logger.info(f"Connected to Velociraptor at {self._config['api_connection_string']}")

    def _run_vql_sync(self, vql: str) -> list[dict[str, Any]]:
        """Execute a VQL query synchronously. Call from async via to_thread."""
        self._ensure_connected()

        request = _api_pb2.VQLCollectorArgs(
            Query=[_api_pb2.VQLRequest(VQL=vql)]
        )
        results: list[dict[str, Any]] = []

        for resp in self._stub.Query(request):
            if hasattr(resp, "error") and resp.error:
                raise RuntimeError(f"Velociraptor API error: {resp.error}")
            if hasattr(resp, "Response") and resp.Response:
                results.extend(json.loads(resp.Response))

        return results

    async def run_vql(self, vql: str) -> list[dict[str, Any]]:
        """Execute a VQL query asynchronously."""
        return await asyncio.to_thread(self._run_vql_sync, vql)

    async def find_client(self, hostname: str) -> dict[str, Any] | None:
        """
        Find a Velociraptor client by hostname or FQDN.

        Args:
            hostname: Hostname or FQDN to search for

        Returns:
            Client info dict or None if not found
        """
        hostname = _sanitize_hostname(hostname)
        vql = (
            f"SELECT client_id,"
            "timestamp(epoch=first_seen_at) as FirstSeen,"
            "timestamp(epoch=last_seen_at) as LastSeen,"
            "os_info.hostname as Hostname,"
            "os_info.fqdn as Fqdn,"
            "os_info.system as OSType,"
            "os_info.release as OS,"
            "os_info.machine as Machine,"
            "agent_information.version as AgentVersion "
            f"FROM clients() WHERE os_info.hostname =~ '^{hostname}$' "
            f"OR os_info.fqdn =~ '^{hostname}$' "
            "ORDER BY LastSeen DESC LIMIT 1"
        )

        results = await self.run_vql(vql)
        return results[0] if results else None

    async def collect_realtime(
        self,
        client_id: str,
        artifact: str,
        parameters: str = "",
        fields: str = "*",
        result_scope: str = "",
    ) -> list[dict[str, Any]]:
        """
        Collect an artifact in real-time and return results.

        Args:
            client_id: Velociraptor client ID (C.xxxx format)
            artifact: Artifact name (e.g. Windows.System.Pslist)
            parameters: Comma-separated key='value' pairs
            fields: Comma-separated field names or '*'
            result_scope: Sub-scope within artifact results (e.g. '/Analysis')

        Returns:
            List of result dicts
        """
        client_id = _sanitize_client_id(client_id)
        artifact = _sanitize_artifact(artifact)
        result_scope = _sanitize_result_scope(result_scope)
        fields = _sanitize_fields(fields)

        env_dict = f"dict({parameters})" if parameters else "dict()"
        vql = (
            f"LET collection <= collect_client("
            f"urgent='TRUE',client_id='{client_id}',"
            f"artifacts='{artifact}',env={env_dict}) "
            f"LET get_monitoring = SELECT * FROM watch_monitoring("
            f"artifact='System.Flow.Completion') "
            f"WHERE FlowId = collection.flow_id LIMIT 1 "
            f"LET get_results = SELECT * FROM source("
            f"client_id=collection.request.client_id,"
            f"flow_id=collection.flow_id,"
            f"artifact='{artifact}{result_scope}') "
            f"SELECT {fields} FROM foreach("
            f"row=get_monitoring,query=get_results)"
        )

        return await self.run_vql(vql)

    async def start_collection(
        self,
        client_id: str,
        artifact: str,
        parameters: str = "",
    ) -> list[dict[str, Any]]:
        """
        Start an artifact collection without waiting for results.

        Args:
            client_id: Velociraptor client ID
            artifact: Artifact name
            parameters: Comma-separated key='value' pairs

        Returns:
            Flow metadata including flow_id
        """
        client_id = _sanitize_client_id(client_id)
        artifact = _sanitize_artifact(artifact)

        env_dict = f"dict({parameters})" if parameters else "dict()"
        vql = (
            f"LET collection <= collect_client("
            f"urgent='TRUE',client_id='{client_id}',"
            f"artifacts='{artifact}',env={env_dict}) "
            f"SELECT flow_id,request.artifacts as artifacts,"
            f"request.specs[0] as specs "
            f"FROM foreach(row=collection)"
        )

        return await self.run_vql(vql)

    async def get_flow_status(
        self,
        client_id: str,
        flow_id: str,
        artifact: str,
    ) -> str:
        """
        Check if a flow has completed.

        Returns:
            'FINISHED' or 'RUNNING'
        """
        client_id = _sanitize_client_id(client_id)
        flow_id = _sanitize_flow_id(flow_id)
        artifact = _sanitize_artifact(artifact)

        vql = (
            f"SELECT * FROM flow_logs("
            f"client_id='{client_id}',flow_id='{flow_id}') "
            f"WHERE message =~ '^Collection {artifact} is done after' "
            f"LIMIT 100"
        )

        results = await self.run_vql(vql)
        return "FINISHED" if results else "RUNNING"

    async def get_flow_results(
        self,
        client_id: str,
        flow_id: str,
        artifact: str,
        fields: str = "*",
    ) -> list[dict[str, Any]]:
        """
        Retrieve results from a completed flow.

        Args:
            client_id: Velociraptor client ID
            flow_id: Flow ID from start_collection
            artifact: Artifact name
            fields: Comma-separated field names or '*'

        Returns:
            List of result dicts
        """
        client_id = _sanitize_client_id(client_id)
        flow_id = _sanitize_flow_id(flow_id)
        artifact = _sanitize_artifact(artifact)
        fields = _sanitize_fields(fields)

        vql = (
            f"SELECT {fields} FROM source("
            f"client_id='{client_id}',"
            f"flow_id='{flow_id}',"
            f"artifact='{artifact}')"
        )

        return await self.run_vql(vql)

    async def list_artifacts(self, os_filter: str = "windows") -> list[dict[str, Any]]:
        """
        List available artifacts filtered by OS.

        Args:
            os_filter: OS filter regex (e.g. 'windows', 'linux')

        Returns:
            List of artifact summaries
        """
        os_filter = _sanitize_regex(os_filter)

        vql = (
            "LET params(data) = SELECT name FROM data "
            "SELECT name, description, params(data=parameters) AS parameters "
            "FROM artifact_definitions() "
            f"WHERE type =~ 'client' AND name =~ '^{os_filter}\\.'"
        )

        def shorten(desc: str) -> str:
            return desc.strip().split(".")[0][:120].rstrip() + "..." if desc else ""

        results = await self.run_vql(vql)
        return [
            {
                "name": r["name"],
                "short_description": shorten(r.get("description", "")),
                "parameters": [p["name"] for p in r.get("parameters", [])],
            }
            for r in results
        ]
