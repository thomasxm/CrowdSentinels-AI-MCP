import logging
import sys
import argparse
import os
from pathlib import Path

from fastmcp import FastMCP

from src.logging_config import configure_logging, get_log_file_path
from src.clients import create_search_client
from src.clients.common.rule_loader import RuleLoader
from src.clients.common.hunting_rule_loader import HuntingRuleLoader
from src.clients.common.esql_client import ESQLClient, ESQLNotSupportedError
from src.tools.alias import AliasTools
from src.tools.cluster import ClusterTools
from src.tools.data_stream import DataStreamTools
from src.tools.document import DocumentTools
from src.tools.general import GeneralTools
from src.tools.index import IndexTools
from src.tools.asset_discovery import AssetDiscoveryTools
from src.tools.eql_query import EQLQueryTools
from src.tools.threat_hunting import ThreatHuntingTools
from src.tools.ioc_analysis import IoCAnalysisTools
from src.tools.smart_search import SmartSearchTools
from src.tools.rule_management import RuleManagementTools
from src.tools.investigation_prompts import InvestigationPromptsTools
from src.tools.chainsaw_hunting import ChainsawHuntingTools
from src.tools.investigation_state_tools import InvestigationStateTools
from src.tools.wireshark_tools import WiresharkTools
from src.tools.esql_hunting import ESQLHuntingTools
from src.tools.workflow_guidance import WorkflowGuidanceTools
from src.tools.schema_resources import SchemaTools
from src.tools.register import ToolsRegister
from src.paths import get_rules_dir, get_hunting_rules_dir, get_toml_rules_dir
from src.version import __version__ as VERSION

class SearchMCPServer:
    def __init__(self, engine_type):
        # Set engine type
        self.engine_type = engine_type
        self.name = "crowdsentinel-mcp-server"
        self.mcp = FastMCP(self.name)

        # Configure logging with file output for debugging
        # Logs go to: /tmp/crowdsentinel/mcp-server.log
        # Override with CROWDSENTINEL_LOG_FILE environment variable
        configure_logging("crowdsentinel")
        self.logger = logging.getLogger("crowdsentinel.server")
        self.logger.info(f"Initialising {self.name}, Version: {VERSION}")

        # Create the corresponding search client
        self.search_client = create_search_client(self.engine_type)

        # Initialize rule loader
        self.rule_loader = self._initialize_rule_loader()

        # Initialize ES|QL hunting components (Elasticsearch only)
        self.hunting_loader = None
        self.esql_client = None
        if self.engine_type == "elasticsearch":
            self._initialize_esql_components()

        # Initialize tools
        self._register_tools()

    def _initialize_rule_loader(self):
        """Initialise the detection rule loader."""
        rules_dir = get_rules_dir()
        toml_rules_dir = get_toml_rules_dir()

        if rules_dir is None and toml_rules_dir is None:
            self.logger.warning("Rules directory not found in any candidate location")
            self.logger.warning("Detection rules will not be available")
            return None

        self.logger.info(f"Loading detection rules from: {rules_dir}")
        if toml_rules_dir:
            self.logger.info(f"Loading TOML detection rules from: {toml_rules_dir}")

        # Create and load rules
        rule_loader = RuleLoader(
            str(rules_dir) if rules_dir else "",
            toml_rules_directory=str(toml_rules_dir) if toml_rules_dir else None,
        )
        loaded_count = rule_loader.load_all_rules()

        if loaded_count > 0:
            stats = rule_loader.get_statistics()
            self.logger.info(f"Loaded {loaded_count} detection rules")
            self.logger.info(f"  - Platforms: {', '.join(stats['platforms'][:10])}")
            self.logger.info(f"  - Types: Lucene={stats['by_type'].get('lucene', 0)}, EQL={stats['by_type'].get('eql', 0)}, ES|QL={stats['by_type'].get('esql', 0)}")
        else:
            self.logger.warning("No detection rules loaded")

        return rule_loader

    def _initialize_esql_components(self):
        """Initialise ES|QL hunting components (Elasticsearch 8.11+ only)."""
        hunting_dir = get_hunting_rules_dir()

        # Initialise hunting rule loader
        if hunting_dir is not None:
            self.logger.info(f"Loading ES|QL hunting rules from: {hunting_dir}")
            self.hunting_loader = HuntingRuleLoader(str(hunting_dir))
            stats = self.hunting_loader.get_statistics()
            self.logger.info(f"Loaded {stats['total_rules']} ES|QL hunting rules with {stats['total_esql_queries']} queries")
            if stats.get('platforms'):
                self.logger.info(f"  - Platforms: {', '.join(stats['platforms'].keys())}")
        else:
            self.logger.warning("Hunting rules directory not found in any candidate location")
            self.logger.warning("ES|QL hunting tools will have no curated rules")

        # Initialize ES|QL client - share config from search client
        self.esql_client = ESQLClient(self.search_client.config, engine_type="elasticsearch")
        # Share the same ES connection to avoid duplicate connections
        self.esql_client.client = self.search_client.client

        self.logger.info("ES|QL client initialised (version check will occur on first query)")

    def _register_tools(self):
        """Register all MCP tools."""
        # Create a tools register
        register = ToolsRegister(self.logger, self.search_client, self.mcp)

        # Define all tool classes to register
        tool_classes = [
            IndexTools,
            DocumentTools,
            ClusterTools,
            AliasTools,
            DataStreamTools,
            GeneralTools,
            # Threat Hunting and IR Tools
            AssetDiscoveryTools,
            EQLQueryTools,
            ThreatHuntingTools,
            IoCAnalysisTools,
            # Smart Search Tools (token-efficient)
            SmartSearchTools,
        ]
        # Register all tools
        register.register_all_tools(tool_classes)

        # Register rule management tools if rules were loaded
        if self.rule_loader:
            self.logger.info("Registering rule management tools")
            rule_tools = RuleManagementTools(self.rule_loader, self.search_client)
            rule_tools.logger = self.logger
            rule_tools.search_client = self.search_client
            rule_tools.rule_loader = self.rule_loader

            # Use the same registration pattern
            from src.clients.exceptions import with_exception_handling
            with_exception_handling(rule_tools, self.mcp)
        else:
            self.logger.warning("Rule management tools not registered (no rules loaded)")

        # Register investigation prompts tools
        self.logger.info("Registering investigation prompts tools")
        investigation_tools = InvestigationPromptsTools(self.search_client)
        investigation_tools.logger = self.logger
        investigation_tools.search_client = self.search_client

        from src.clients.exceptions import with_exception_handling
        with_exception_handling(investigation_tools, self.mcp)

        # Register Chainsaw hunting tools
        self.logger.info("Registering Chainsaw hunting tools")
        chainsaw_tools = ChainsawHuntingTools()
        chainsaw_tools.logger = self.logger

        with_exception_handling(chainsaw_tools, self.mcp)

        # Register Investigation State tools
        self.logger.info("Registering Investigation State tools")
        investigation_state_tools = InvestigationStateTools()
        investigation_state_tools.logger = self.logger

        with_exception_handling(investigation_state_tools, self.mcp)

        # Register Wireshark network analysis tools
        self.logger.info("Registering Wireshark network analysis tools")
        wireshark_tools = WiresharkTools()
        wireshark_tools.logger = self.logger

        with_exception_handling(wireshark_tools, self.mcp)

        # Register ES|QL hunting tools (Elasticsearch only)
        if self.hunting_loader and self.esql_client:
            self.logger.info("Registering ES|QL hunting tools")
            esql_tools = ESQLHuntingTools(self.hunting_loader, self.esql_client)
            esql_tools.logger = self.logger

            with_exception_handling(esql_tools, self.mcp)
        else:
            self.logger.info("ES|QL hunting tools not registered (not available for this engine)")

        # Register Workflow Guidance (resources, prompts, and tools)
        # This ensures ALL connected AI agents know the investigation workflow
        self.logger.info("Registering Workflow Guidance (resources, prompts, tools)")
        workflow_tools = WorkflowGuidanceTools()
        workflow_tools.register_tools(self.mcp)

        # Register Schema Tools (resources and introspection tools)
        # Provides schema discovery, field mapping lookups, and schema-aware query building
        self.logger.info("Registering Schema Tools (resources, introspection)")
        schema_tools = SchemaTools(self.search_client)
        schema_tools.register_tools(self.mcp)


def run_search_server(engine_type, transport, host, port, path):
    """Run search server with specified engine type and transport options.
    
    Args:
        engine_type: Type of search engine to use ("elasticsearch" or "opensearch")
        transport: Transport protocol to use ("stdio", "streamable-http", or "sse")
        host: Host to bind to when using HTTP transports
        port: Port to bind to when using HTTP transports
        path: URL path prefix for HTTP transports
    """
    
    server = SearchMCPServer(engine_type=engine_type)
    
    if transport in ["streamable-http", "sse"]:
        server.logger.info(f"Starting {server.name} with {transport} transport on {host}:{port}{path}")
        server.logger.info(f"Logs visible in this terminal - tool calls will appear here")
        server.mcp.run(transport=transport, host=host, port=port, path=path)
    else:
        # stdio transport - logs go to file since stdout/stderr are captured by MCP client
        log_file = get_log_file_path()
        server.logger.info(f"Starting {server.name} with {transport} transport")
        server.logger.info(f"View logs: tail -f {log_file}")
        server.mcp.run(transport=transport)

def parse_server_args():
    """Parse command line arguments for the MCP server.
    
    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--transport", "-t",
        default="stdio",
        choices=["stdio", "streamable-http", "sse"],
        help="Transport protocol to use (default: stdio)"
    )
    parser.add_argument(
        "--host", "-H",
        default="127.0.0.1",
        help="Host to bind to when using HTTP transports (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        default=8000,
        help="Port to bind to when using HTTP transports (default: 8000)"
    )
    parser.add_argument(
        "--path", "-P",
        help="URL path prefix for HTTP transports (default: /mcp/ for streamable-http, /sse/ for sse)"
    )
    
    args = parser.parse_args()
    
    # Set default path based on transport type if not specified
    # Use trailing slash to avoid 307 redirects on every request
    if args.path is None:
        if args.transport == "sse":
            args.path = "/sse/"
        else:
            args.path = "/mcp/"
            
    return args

def elasticsearch_mcp_server():
    """Entry point for Elasticsearch MCP server."""
    args = parse_server_args()
    
    # Run the server with the specified options
    run_search_server(
        engine_type="elasticsearch",
        transport=args.transport,
        host=args.host,
        port=args.port,
        path=args.path
    )

def opensearch_mcp_server():
    """Entry point for OpenSearch MCP server."""
    args = parse_server_args()
    
    # Run the server with the specified options
    run_search_server(
        engine_type="opensearch",
        transport=args.transport,
        host=args.host,
        port=args.port,
        path=args.path
    )

if __name__ == "__main__":
    # Require crowdsentinel-mcp-server or crowdsentinel-opensearch-mcp-server as the first argument
    if len(sys.argv) <= 1 or sys.argv[1] not in ["crowdsentinel-mcp-server", "crowdsentinel-opensearch-mcp-server"]:
        print("Error: First argument must be 'crowdsentinel-mcp-server' or 'crowdsentinel-opensearch-mcp-server'")
        sys.exit(1)
        
    # Determine engine type based on the first argument
    engine_type = "elasticsearch"  # Default
    if sys.argv[1] == "crowdsentinel-opensearch-mcp-server":
        engine_type = "opensearch"
        
    # Remove the first argument so it doesn't interfere with argparse
    sys.argv.pop(1)
    
    # Parse command line arguments
    args = parse_server_args()
    
    # Run the server with the specified options
    run_search_server(
        engine_type=engine_type,
        transport=args.transport,
        host=args.host,
        port=args.port,
        path=args.path
    )
