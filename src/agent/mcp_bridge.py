"""Bridge between the agent loop and MCP tool servers.

Routes tool calls to either:
    - CrowdSentinel's own tools (in-process via FastMCP)
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
    """Aggregate tools from CrowdSentinel (in-process) and external MCP servers."""

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
        self._started = False

    def start(self) -> None:
        """Discover tools from all sources."""
        if self._started:
            return

        # 1. Load CrowdSentinel tools in-process
        self._load_crowdsentinel_tools()

        # 2. Start and connect to external MCP servers
        for config in self._external_configs:
            self._start_external_server(config)

        self._started = True
        logger.info(
            "MCP Bridge ready: %d tools from %d server(s)",
            len(self._tool_registry),
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

    def _start_external_server(self, config: MCPServerConfig) -> None:
        """Start an external MCP server and discover its tools via stdio JSON-RPC."""
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
                "id": 1,
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

            # List tools
            tools_request = {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {},
            }
            self._send_jsonrpc(proc, tools_request)
            tools_response = self._recv_jsonrpc(proc, timeout=10)

            if not tools_response or "error" in tools_response:
                logger.warning("Failed to list tools from %s: %s", config.name, tools_response)
                return

            tools = tools_response.get("result", {}).get("tools", [])
            for tool in tools:
                tool_name = tool["name"]
                # Prefix with server name if collision
                if tool_name in self._tool_registry:
                    prefixed = f"{config.name}__{tool_name}"
                    logger.info("Tool name collision: %s → %s", tool_name, prefixed)
                    tool_name = prefixed

                schema = {
                    "name": tool_name,
                    "description": tool.get("description", ""),
                    "inputSchema": tool.get("inputSchema", {}),
                }
                self._tool_registry[tool_name] = (config.name, tool)
                self._tool_schemas.append(schema)

            logger.info("Loaded %d tools from external server: %s", len(tools), config.name)

        except FileNotFoundError:
            logger.error("External MCP server command not found: %s", cmd)
        except Exception as exc:
            logger.error("Failed to start external MCP server %s: %s", config.name, exc)

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
            "id": 3,
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
