"""Load and merge MCP server configurations for agent mode.

Configuration sources (merged in order):
    1. ~/.crowdsentinel/mcp-servers.json  (persistent config)
    2. --mcp-server CLI flags             (additions for this run)
    3. --no-mcp-server CLI flags          (exclusions for this run)

Config format matches Claude Desktop's claude_desktop_config.json:
    {
      "mcpServers": {
        "server-name": {
          "command": "uvx",
          "args": ["package-name"],
          "env": {"KEY": "value"}
        }
      }
    }
"""

import json
import logging
import shlex
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger("crowdsentinel.agent.config")


@dataclass
class MCPServerConfig:
    """Configuration for an external MCP server."""
    name: str
    command: str
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)


def _load_config_file() -> dict[str, MCPServerConfig]:
    """Load MCP server configs from ~/.crowdsentinel/mcp-servers.json."""
    config_path = Path.home() / ".crowdsentinel" / "mcp-servers.json"
    if not config_path.is_file():
        return {}

    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Failed to load %s: %s", config_path, exc)
        return {}

    servers = {}
    for name, spec in data.get("mcpServers", {}).items():
        if not isinstance(spec, dict) or "command" not in spec:
            logger.warning("Skipping invalid server config: %s", name)
            continue
        servers[name] = MCPServerConfig(
            name=name,
            command=spec["command"],
            args=spec.get("args", []),
            env=spec.get("env", {}),
        )

    if servers:
        logger.info("Loaded %d MCP server(s) from %s: %s", len(servers), config_path, ", ".join(servers))

    return servers


def _parse_cli_servers(cli_servers: list[str] | None) -> dict[str, MCPServerConfig]:
    """Parse --mcp-server CLI flags.

    Format: "name:command args..."
    Example: "virustotal:uvx virustotal-mcp-server"
    """
    if not cli_servers:
        return {}

    servers = {}
    for entry in cli_servers:
        if ":" not in entry:
            logger.warning("Invalid --mcp-server format (expected name:command): %s", entry)
            continue

        name, cmd_str = entry.split(":", 1)
        name = name.strip()
        parts = shlex.split(cmd_str.strip())
        if not parts:
            logger.warning("Empty command for --mcp-server %s", name)
            continue

        servers[name] = MCPServerConfig(
            name=name,
            command=parts[0],
            args=parts[1:],
        )

    return servers


def load_mcp_config(
    cli_add: list[str] | None = None,
    cli_exclude: list[str] | None = None,
) -> list[MCPServerConfig]:
    """Load and merge MCP server configurations.

    Args:
        cli_add: --mcp-server flags ("name:command args...")
        cli_exclude: --no-mcp-server flags (server names to exclude)

    Returns:
        Final list of external MCP server configs (CrowdSentinel is handled separately).
    """
    # 1. Load config file
    servers = _load_config_file()

    # 2. Merge CLI additions (override file entries with same name)
    cli_servers = _parse_cli_servers(cli_add)
    servers.update(cli_servers)

    # 3. Apply CLI exclusions
    if cli_exclude:
        for name in cli_exclude:
            removed = servers.pop(name.strip(), None)
            if removed:
                logger.info("Excluded MCP server: %s", name)
            else:
                logger.warning("--no-mcp-server %s: not found in config", name)

    return list(servers.values())
