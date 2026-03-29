"""Bridge between the agent loop and MCP tool servers.

Routes tool calls and resource reads to either:
    - CrowdSentinel's own tools/resources (in-process via FastMCP)
    - External MCP servers (spawned as subprocesses via stdio transport)
"""

import asyncio
import json
import logging
import subprocess
from typing import Any

from src.agent.config import MCPServerConfig

logger = logging.getLogger("crowdsentinel.agent.bridge")


class MCPBridge:
    """Aggregate tools and resources from CrowdSentinel (in-process) and external MCP servers."""

    def __init__(
        self,
        crowdsentinel_server,
        external_configs: list[MCPServerConfig],
    ):
        self._cs_server = crowdsentinel_server  # SearchMCPServer instance
        self._external_configs = external_configs
        self._external_procs: dict[str, subprocess.Popen] = {}
        self._tool_registry: dict[str, tuple[str, Any]] = {}  # tool_name -> (server_name, tool_obj)
        self._tool_schemas: list[dict[str, Any]] = []
        self._resource_registry: dict[str, tuple[str, Any]] = {}  # uri -> (server_name, resource_obj_or_None)
        self._resource_cache: dict[str, str] = {}  # uri -> content (pre-loaded for in-process)
        self._started = False
        self._next_jsonrpc_id = 10  # Start higher to avoid collision with init sequence

    def start(self) -> None:
        """Discover tools and resources from all sources."""
        if self._started:
            return

        # 1. Load CrowdSentinel tools and resources in-process
        self._load_crowdsentinel_tools()
        self._load_crowdsentinel_resources()

        # 2. Start and connect to external MCP servers
        for config in self._external_configs:
            self._start_external_server(config)

        self._started = True
        logger.info(
            "MCP Bridge ready: %d tools, %d resources from %d server(s)",
            len(self._tool_registry),
            len(self._resource_registry),
            1 + len(self._external_procs),
        )

    def stop(self) -> None:
        """Clean up external server subprocesses."""
        for name, proc in self._external_procs.items():
            try:
                proc.terminate()
                proc.wait(timeout=5)
                logger.info("Stopped external MCP server: %s", name)
            except Exception as exc:
                logger.warning("Failed to stop %s: %s", name, exc)
                try:
                    proc.kill()
                except Exception:
                    pass
        self._external_procs.clear()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()

    # -----------------------------------------------------------------
    # Tool API (existing)
    # -----------------------------------------------------------------

    def list_tools(self) -> list[dict[str, Any]]:
        """Return all available tool schemas in MCP format."""
        return list(self._tool_schemas)

    def execute_tool(self, name: str, arguments: dict[str, Any]) -> str:
        """Execute a tool by name and return the result as a string."""
        if name not in self._tool_registry:
            return json.dumps({"error": f"Unknown tool: {name}"})

        server_name, tool_obj = self._tool_registry[name]

        if server_name == "crowdsentinel":
            return self._execute_crowdsentinel_tool(tool_obj, arguments)
        return self._execute_external_tool(server_name, name, arguments)

    # -----------------------------------------------------------------
    # Resource API (new)
    # -----------------------------------------------------------------

    def list_resources(self) -> list[dict[str, str]]:
        """Return all available resource URIs with metadata.

        Returns:
            List of dicts with 'uri', 'server', and 'description' keys.
        """
        if not hasattr(self, "_resource_registry"):
            return []
        result = []
        for uri, (server_name, resource_obj) in self._resource_registry.items():
            desc = ""
            if resource_obj is not None and hasattr(resource_obj, "description"):
                desc = resource_obj.description or ""
            result.append({"uri": uri, "server": server_name, "description": desc})
        return result

    def read_resource(self, uri: str) -> str:
        """Read a resource by URI and return its content as a string.

        For in-process resources, reads directly from FastMCP.
        For external servers, sends a JSON-RPC resources/read request.

        Args:
            uri: The resource URI (e.g. 'crowdsentinel://ioc-reference')

        Returns:
            Resource content as a string, or JSON error.
        """
        if uri not in self._resource_registry:
            return json.dumps({"error": f"Unknown resource: {uri}"})

        server_name, _resource_obj = self._resource_registry[uri]

        if server_name == "crowdsentinel":
            return self._read_crowdsentinel_resource(uri)
        return self._read_external_resource(server_name, uri)

    # -----------------------------------------------------------------
    # In-process loading (CrowdSentinel)
    # -----------------------------------------------------------------

    def _load_crowdsentinel_tools(self) -> None:
        """Load tools from the in-process CrowdSentinel MCP server."""
        mcp = self._cs_server.mcp

        # FastMCP.get_tools() is async
        loop = asyncio.new_event_loop()
        try:
            tools = loop.run_until_complete(mcp.get_tools())
        finally:
            loop.close()

        for tool_name, tool_obj in tools.items():
            mcp_tool = tool_obj.to_mcp_tool()
            schema = {
                "name": mcp_tool.name,
                "description": mcp_tool.description or "",
                "inputSchema": mcp_tool.inputSchema or {},
            }
            self._tool_registry[tool_name] = ("crowdsentinel", tool_obj)
            self._tool_schemas.append(schema)

        logger.info("Loaded %d CrowdSentinel tools", len(tools))

    def _load_crowdsentinel_resources(self) -> None:
        """Load resources from the in-process CrowdSentinel MCP server.

        Discovers all registered resources and stores them in the registry.
        Resources are read lazily on first access via read_resource().
        """
        mcp = self._cs_server.mcp

        loop = asyncio.new_event_loop()
        try:
            resources = loop.run_until_complete(mcp.get_resources())
        finally:
            loop.close()

        for uri, resource_obj in resources.items():
            self._resource_registry[uri] = ("crowdsentinel", resource_obj)

        logger.info("Loaded %d CrowdSentinel resources", len(resources))

    def _read_crowdsentinel_resource(self, uri: str) -> str:
        """Read a resource from the in-process CrowdSentinel MCP server."""
        # Check cache first
        if uri in self._resource_cache:
            return self._resource_cache[uri]

        mcp = self._cs_server.mcp

        loop = asyncio.new_event_loop()
        try:
            content = loop.run_until_complete(mcp._resource_manager.read_resource(uri))
        finally:
            loop.close()

        # Content may be str, bytes, dict, or list
        if isinstance(content, bytes):
            result = content.decode("utf-8", errors="replace")
        elif isinstance(content, str):
            result = content
        else:
            result = json.dumps(content, default=str, indent=2)

        # Cache for subsequent reads
        self._resource_cache[uri] = result
        return result

    def _execute_crowdsentinel_tool(self, tool_obj: Any, arguments: dict[str, Any]) -> str:
        """Execute a CrowdSentinel tool in-process."""
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(tool_obj.run(arguments))
        finally:
            loop.close()

        # Result is List[TextContent] — extract text
        if isinstance(result, list):
            texts = []
            for item in result:
                if hasattr(item, "text"):
                    texts.append(item.text)
                elif isinstance(item, dict):
                    texts.append(item.get("text", str(item)))
                else:
                    texts.append(str(item))
            return "\n".join(texts)

        if isinstance(result, str):
            return result

        return json.dumps(result, default=str)

    # -----------------------------------------------------------------
    # External MCP servers (subprocess via stdio JSON-RPC)
    # -----------------------------------------------------------------

    def _next_id(self) -> int:
        """Get next JSON-RPC request ID."""
        self._next_jsonrpc_id += 1
        return self._next_jsonrpc_id

    def _start_external_server(self, config: MCPServerConfig) -> None:
        """Start an external MCP server and discover its tools and resources."""
        cmd = [config.command] + config.args
        env = {**dict(__import__("os").environ), **config.env} if config.env else None

        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
            self._external_procs[config.name] = proc

            # Send initialize request
            init_request = {
                "jsonrpc": "2.0",
                "id": self._next_id(),
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "crowdsentinel-agent", "version": "1.0"},
                },
            }
            self._send_jsonrpc(proc, init_request)
            init_response = self._recv_jsonrpc(proc, timeout=10)

            if not init_response or "error" in init_response:
                logger.warning("Failed to initialize %s: %s", config.name, init_response)
                return

            # Send initialized notification
            self._send_jsonrpc(
                proc,
                {
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                },
            )

            # Discover tools
            self._discover_external_tools(proc, config.name)

            # Discover resources
            self._discover_external_resources(proc, config.name)

        except FileNotFoundError:
            logger.error("External MCP server command not found: %s", cmd)
        except Exception as exc:
            logger.error("Failed to start external MCP server %s: %s", config.name, exc)

    def _discover_external_tools(self, proc: subprocess.Popen, server_name: str) -> None:
        """Discover tools from an external MCP server via JSON-RPC."""
        tools_request = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "tools/list",
            "params": {},
        }
        self._send_jsonrpc(proc, tools_request)
        tools_response = self._recv_jsonrpc(proc, timeout=10)

        if not tools_response or "error" in tools_response:
            logger.warning("Failed to list tools from %s: %s", server_name, tools_response)
            return

        tools = tools_response.get("result", {}).get("tools", [])
        for tool in tools:
            tool_name = tool["name"]
            # Prefix with server name if collision
            if tool_name in self._tool_registry:
                prefixed = f"{server_name}__{tool_name}"
                logger.info("Tool name collision: %s -> %s", tool_name, prefixed)
                tool_name = prefixed

            schema = {
                "name": tool_name,
                "description": tool.get("description", ""),
                "inputSchema": tool.get("inputSchema", {}),
            }
            self._tool_registry[tool_name] = (server_name, tool)
            self._tool_schemas.append(schema)

        logger.info("Loaded %d tools from external server: %s", len(tools), server_name)

    def _discover_external_resources(self, proc: subprocess.Popen, server_name: str) -> None:
        """Discover resources from an external MCP server via JSON-RPC."""
        resources_request = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "resources/list",
            "params": {},
        }
        self._send_jsonrpc(proc, resources_request)
        resources_response = self._recv_jsonrpc(proc, timeout=10)

        if not resources_response or "error" in resources_response:
            # Not all servers support resources — this is fine
            logger.debug("No resources from %s (may not support resources/list)", server_name)
            return

        resources = resources_response.get("result", {}).get("resources", [])
        for resource in resources:
            uri = resource.get("uri", "")
            if not uri:
                continue
            # Store with None as resource_obj (external servers use JSON-RPC to read)
            self._resource_registry[uri] = (server_name, None)

        if resources:
            logger.info("Loaded %d resources from external server: %s", len(resources), server_name)

    def _read_external_resource(self, server_name: str, uri: str) -> str:
        """Read a resource from an external MCP server via JSON-RPC."""
        # Check cache
        if uri in self._resource_cache:
            return self._resource_cache[uri]

        proc = self._external_procs.get(server_name)
        if not proc or proc.poll() is not None:
            return json.dumps({"error": f"External server {server_name} is not running"})

        request = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "resources/read",
            "params": {"uri": uri},
        }

        self._send_jsonrpc(proc, request)
        response = self._recv_jsonrpc(proc, timeout=10)

        if not response:
            return json.dumps({"error": f"No response from {server_name} for resource {uri}"})

        if "error" in response:
            return json.dumps({"error": response["error"]})

        # MCP resources/read returns { contents: [{ uri, text|blob, mimeType }] }
        contents = response.get("result", {}).get("contents", [])
        texts = []
        for item in contents:
            if isinstance(item, dict):
                text = item.get("text", "")
                if text:
                    texts.append(text)

        result = "\n".join(texts) if texts else json.dumps(response.get("result", {}), default=str)

        # Cache
        self._resource_cache[uri] = result
        return result

    def _execute_external_tool(self, server_name: str, tool_name: str, arguments: dict[str, Any]) -> str:
        """Execute a tool on an external MCP server via JSON-RPC."""
        proc = self._external_procs.get(server_name)
        if not proc or proc.poll() is not None:
            return json.dumps({"error": f"External server {server_name} is not running"})

        # Strip server prefix if present
        original_name = tool_name
        if tool_name.startswith(f"{server_name}__"):
            original_name = tool_name[len(f"{server_name}__") :]

        request = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": "tools/call",
            "params": {
                "name": original_name,
                "arguments": arguments,
            },
        }

        self._send_jsonrpc(proc, request)
        response = self._recv_jsonrpc(proc, timeout=60)

        if not response:
            return json.dumps({"error": f"No response from {server_name}"})

        if "error" in response:
            return json.dumps({"error": response["error"]})

        result = response.get("result", {})
        content = result.get("content", [])

        texts = []
        for item in content:
            if isinstance(item, dict) and item.get("type") == "text":
                texts.append(item.get("text", ""))

        return "\n".join(texts) if texts else json.dumps(result, default=str)

    # -----------------------------------------------------------------
    # JSON-RPC transport helpers
    # -----------------------------------------------------------------

    @staticmethod
    def _send_jsonrpc(proc: subprocess.Popen, message: dict) -> None:
        """Send a JSON-RPC message via stdio."""
        body = json.dumps(message)
        header = f"Content-Length: {len(body)}\r\n\r\n"
        proc.stdin.write(header.encode() + body.encode())
        proc.stdin.flush()

    @staticmethod
    def _recv_jsonrpc(proc: subprocess.Popen, timeout: int = 10) -> dict | None:
        """Receive a JSON-RPC response via stdio."""
        import select

        # Read Content-Length header
        header = b""
        while True:
            ready, _, _ = select.select([proc.stdout], [], [], timeout)
            if not ready:
                return None
            byte = proc.stdout.read(1)
            if not byte:
                return None
            header += byte
            if header.endswith(b"\r\n\r\n"):
                break

        # Parse content length
        header_str = header.decode("utf-8", errors="replace")
        content_length = 0
        for line in header_str.split("\r\n"):
            if line.lower().startswith("content-length:"):
                content_length = int(line.split(":", 1)[1].strip())
                break

        if content_length == 0:
            return None

        # Read body
        body = b""
        while len(body) < content_length:
            ready, _, _ = select.select([proc.stdout], [], [], timeout)
            if not ready:
                return None
            chunk = proc.stdout.read(content_length - len(body))
            if not chunk:
                return None
            body += chunk

        try:
            return json.loads(body.decode("utf-8"))
        except json.JSONDecodeError:
            return None
