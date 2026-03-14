"""CrowdSentinel CLI — command-line threat hunting from the terminal.

Provides the same capabilities as the MCP tools, accessible via
the ``crowdsentinel`` command.
"""

import argparse
import json
import signal
import sys
from pathlib import Path
from typing import Any, Dict

from dotenv import load_dotenv

from src.version import __version__


# ---------------------------------------------------------------------------
# Output formatting helpers
# ---------------------------------------------------------------------------

def _format_json(data: Any) -> str:
    """Return pretty-printed JSON."""
    return json.dumps(data, indent=2, default=str)


def _format_table(data: Any) -> str:
    """Return a simple human-readable table representation."""
    if isinstance(data, dict):
        lines = []
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                lines.append(f"{key}:")
                lines.append(f"  {_format_json(value)}")
            else:
                lines.append(f"{key}: {value}")
        return "\n".join(lines)
    return _format_json(data)


def _format_summary(data: Any) -> str:
    """Return a compact one-line summary where possible."""
    if isinstance(data, dict):
        # Try to extract meaningful summary fields
        summary_parts = []
        for key in ("status", "cluster_name", "total_hits", "total_found",
                     "total", "count", "hits_count", "detected"):
            if key in data:
                summary_parts.append(f"{key}={data[key]}")
        if summary_parts:
            return " | ".join(summary_parts)
        # Fallback: show top-level keys
        return " | ".join(f"{k}={v}" for k, v in list(data.items())[:8]
                          if not isinstance(v, (dict, list)))
    return str(data)


def _emit(data: Any, output_mode: str) -> None:
    """Write *data* to stdout in the requested format."""
    formatters = {
        "json": _format_json,
        "table": _format_table,
        "summary": _format_summary,
    }
    formatter = formatters.get(output_mode, _format_json)
    sys.stdout.write(formatter(data) + "\n")


# ---------------------------------------------------------------------------
# Client factory (lazy — only created when a subcommand runs)
# ---------------------------------------------------------------------------

def _create_client():
    """Create a SearchClient using the same infrastructure as the MCP server."""
    load_dotenv()
    from src.clients import create_search_client
    return create_search_client("elasticsearch")


def _create_rule_loader():
    """Create and load the detection rule loader."""
    from src.clients.common.rule_loader import RuleLoader

    project_root = Path(__file__).parent.parent.parent
    rules_dir = project_root / "rules"
    if not rules_dir.exists():
        return None
    loader = RuleLoader(str(rules_dir))
    loader.load_all_rules()
    return loader


def _create_esql_client(search_client):
    """Create an ESQLClient sharing the search client's connection."""
    from src.clients.common.esql_client import ESQLClient

    esql = ESQLClient(search_client.config, engine_type="elasticsearch")
    esql.client = search_client.client
    return esql


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------

def _cmd_health(args):
    """Show cluster health information."""
    client = _create_client()
    result = client.get_cluster_health()
    _emit(result, args.output)
    return 0


def _cmd_indices(args):
    """List all indices."""
    client = _create_client()
    result = client.list_indices()
    _emit(result, args.output)
    return 0


def _cmd_hunt(args):
    """Run an IR-focused threat hunt search with IoC extraction."""
    client = _create_client()

    from src.tools.smart_search import SmartSearchTools
    smart = SmartSearchTools(client)

    result = smart._execute_threat_hunt_search(
        index=args.index,
        query=args.query,
        timeframe_minutes=args.timeframe,
        extract_iocs=True,
        map_mitre=True,
        max_sample_events=args.sample_events,
        analysis_size=args.analysis_size,
    )
    _emit(result, args.output)

    # Exit code 2 when no results found
    total = result.get("summary", {}).get("total_hits", 0)
    return 0 if total else 2


def _cmd_eql(args):
    """Execute an EQL query."""
    client = _create_client()
    result = client.eql_search(
        index=args.index,
        query=args.query,
        size=args.size,
    )
    _emit(result, args.output)
    return 0


def _cmd_esql(args):
    """Execute an ES|QL query."""
    client = _create_client()
    esql = _create_esql_client(client)

    if args.auto_discover:
        result = esql.execute_with_auto_discovery(
            query=args.query,
            lean=args.lean,
        )
    else:
        result = esql.execute_query(args.query)
    _emit(result, args.output)
    return 0


def _cmd_detect(args):
    """Execute a detection rule by ID."""
    client = _create_client()
    loader = _create_rule_loader()
    if loader is None:
        print("Error: detection rules directory not found.", file=sys.stderr)
        return 1

    rule = loader.get_rule(args.rule_id)
    if rule is None:
        print(f"Error: rule not found: {args.rule_id}", file=sys.stderr)
        return 1

    if rule.rule_type == "lucene":
        result = client.search_with_lucene(
            index=args.index,
            lucene_query=rule.query,
            timeframe_minutes=args.timeframe if args.timeframe > 0 else None,
            size=min(args.size, 1000),
        )
    elif rule.rule_type == "eql":
        result = client.eql_search(
            index=args.index,
            query=rule.query,
            size=min(args.size, 1000),
        )
    else:
        print(f"Error: unsupported rule type: {rule.rule_type}", file=sys.stderr)
        return 1

    result["rule_info"] = {
        "rule_id": rule.rule_id,
        "name": rule.display_name,
        "platform": rule.platform,
        "log_source": rule.log_source,
        "type": rule.rule_type,
        "mitre_tactics": list(rule.mitre_tactics),
    }
    _emit(result, args.output)
    return 0


def _cmd_rules(args):
    """List available detection rules."""
    loader = _create_rule_loader()
    if loader is None:
        print("Error: detection rules directory not found.", file=sys.stderr)
        return 1

    rules = loader.search_rules(
        platform=args.platform,
        log_source=args.log_source,
        rule_type=args.rule_type,
        search_term=args.search,
        limit=min(args.limit, 200),
    )

    stats = loader.get_statistics()
    summaries = []
    for rule in rules:
        summaries.append({
            "rule_id": rule.rule_id,
            "name": rule.display_name,
            "platform": rule.platform,
            "log_source": rule.log_source,
            "type": rule.rule_type,
            "mitre_tactics": list(rule.mitre_tactics),
        })

    result = {
        "total_found": len(rules),
        "showing": len(summaries),
        "rules": summaries,
        "statistics": {
            "total_rules_loaded": stats["total_rules"],
            "by_platform": stats["by_platform"],
            "by_type": stats["by_type"],
        },
    }
    _emit(result, args.output)
    return 0 if rules else 2


def _cmd_schema(args):
    """Detect which schema matches an index pattern."""
    from src.clients.common.schemas import detect_schema_from_index, list_schemas

    schema = detect_schema_from_index(args.index)
    if schema:
        result = {
            "detected": True,
            "index_pattern": args.index,
            "schema_id": schema.schema_id,
            "schema_name": schema.name,
            "source_type": schema.source_type.value,
            "field_prefix": schema.field_prefix,
            "event_types": list(schema.event_types.keys()),
        }
    else:
        result = {
            "detected": False,
            "index_pattern": args.index,
            "message": "No schema auto-detected. Will fall back to Sysmon schema.",
            "available_schemas": [
                {"schema_id": s["schema_id"], "index_patterns": s["index_patterns"]}
                for s in list_schemas()
            ],
        }

    _emit(result, args.output)
    return 0


def _cmd_ioc(args):
    """Hunt for a specific Indicator of Compromise."""
    client = _create_client()
    result = client.hunt_for_ioc(
        index=args.index,
        ioc=args.value,
        ioc_type=args.type,
        timeframe_minutes=args.timeframe,
    )
    _emit(result, args.output)

    total = result.get("total_hits", result.get("total", 0))
    return 0 if total else 2


def _cmd_pcap(args):
    """Analyse a PCAP file for network threats."""
    from src.tools.wireshark_tools import WiresharkTools
    ws = WiresharkTools()

    if args.action == "overview":
        result = ws._pcap_overview(args.pcap)
    elif args.action == "beaconing":
        result = ws._detect_beaconing(
            args.pcap,
            min_connections=args.min_connections,
        )
    elif args.action == "lateral":
        result = ws._detect_lateral_movement(args.pcap)
    elif args.action == "sessions":
        result = ws._track_sessions(
            args.pcap,
            protocol=args.protocol,
        )
    elif args.action == "iocs":
        if not args.indicators:
            print("Error: --indicators required for ioc hunt", file=sys.stderr)
            return 1
        result = ws._hunt_iocs(
            args.pcap,
            iocs=args.indicators,
        )
    else:
        print(f"Error: unknown action: {args.action}", file=sys.stderr)
        return 1

    _emit(result, args.output)
    return 0


def _cmd_chainsaw(args):
    """Hunt through EVTX logs using Chainsaw with Sigma rules."""
    from src.clients.common.chainsaw_client import ChainsawClient
    client = ChainsawClient()

    if args.action == "hunt":
        if not args.evtx:
            print("Error: EVTX path required for hunt", file=sys.stderr)
            return 1
        # Resolve mapping path relative to chainsaw binary if not found at project root
        mapping_path = args.mapping
        if not mapping_path and not client.mappings.exists():
            chainsaw_dir = client.chainsaw_path.parent
            fallback = chainsaw_dir / "mappings" / "sigma-event-logs-all.yml"
            if fallback.exists():
                mapping_path = str(fallback)
        result = client.hunt(
            evtx_path=args.evtx,
            sigma_path=args.sigma_rules,
            mapping_path=mapping_path,
        )
    elif args.action == "search":
        if not args.evtx or not args.keyword:
            print("Error: EVTX path and --keyword required for search", file=sys.stderr)
            return 1
        result = client.search(
            evtx_path=args.evtx,
            search_term=args.keyword,
        )
    elif args.action == "status":
        result = {
            "chainsaw_path": str(client.chainsaw_path),
            "installed": client.chainsaw_path.exists(),
            "sigma_rules_path": str(client.sigma_rules),
            "sigma_rules_exist": client.sigma_rules.exists(),
        }
    else:
        print(f"Error: unknown action: {args.action}", file=sys.stderr)
        return 1

    _emit(result, args.output)
    return 0


def _cmd_analyse(args):
    """Analyse search results read from stdin (JSON)."""
    raw = sys.stdin.read()
    if not raw.strip():
        print("Error: no JSON received on stdin.", file=sys.stderr)
        return 1

    try:
        search_results = json.loads(raw)
    except json.JSONDecodeError as exc:
        print(f"Error: invalid JSON on stdin: {exc}", file=sys.stderr)
        return 1

    client = _create_client()
    result = client.analyze_search_results(
        search_results=search_results,
        context=args.context or "",
    )
    _emit(result, args.output)
    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser with all subcommands."""

    # Shared parent parser that adds --output to every subcommand
    output_parent = argparse.ArgumentParser(add_help=False)
    output_parent.add_argument(
        "--output", "-o",
        choices=["json", "table", "summary"],
        default="json",
        help="Output format (default: json)",
    )

    parser = argparse.ArgumentParser(
        prog="crowdsentinel",
        description="CrowdSentinel CLI — threat hunting from the terminal.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", "-V",
        action="version",
        version=f"crowdsentinel {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # --- health ----------------------------------------------------------
    sp = subparsers.add_parser(
        "health",
        parents=[output_parent],
        help="Show cluster health",
        epilog="Example:\n  crowdsentinel health\n  crowdsentinel health -o summary",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sp.set_defaults(func=_cmd_health)

    # --- indices ---------------------------------------------------------
    sp = subparsers.add_parser(
        "indices",
        parents=[output_parent],
        help="List all indices",
        epilog="Example:\n  crowdsentinel indices\n  crowdsentinel indices -o table",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sp.set_defaults(func=_cmd_indices)

    # --- hunt ------------------------------------------------------------
    sp = subparsers.add_parser(
        "hunt",
        parents=[output_parent],
        help="IR-focused threat hunt with IoC extraction",
        epilog=(
            "Examples:\n"
            "  crowdsentinel hunt 'event.code:4625' -i winlogbeat-*\n"
            "  crowdsentinel hunt 'powershell' -i winlogbeat-* --timeframe 1440\n"
            "  crowdsentinel hunt 'failed login' -i winlogbeat-* -o summary"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sp.add_argument("query", help="Query string for threat hunting")
    sp.add_argument("-i", "--index", required=True, help="Index pattern (e.g. winlogbeat-*)")
    sp.add_argument("--timeframe", type=int, default=60, help="Time window in minutes (default: 60)")
    sp.add_argument("--sample-events", type=int, default=5, help="Sample events to include (default: 5)")
    sp.add_argument("--analysis-size", type=int, default=50, help="Events to fetch for analysis (default: 50)")
    sp.set_defaults(func=_cmd_hunt)

    # --- eql -------------------------------------------------------------
    sp = subparsers.add_parser(
        "eql",
        parents=[output_parent],
        help="Execute an EQL query",
        epilog=(
            "Examples:\n"
            '  crowdsentinel eql \'process where process.name == "cmd.exe"\' -i winlogbeat-*\n'
            "  crowdsentinel eql 'sequence [process where true] [network where true]' -i winlogbeat-* --size 50"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sp.add_argument("query", help="EQL query string")
    sp.add_argument("-i", "--index", required=True, help="Index pattern")
    sp.add_argument("--size", type=int, default=100, help="Max results (default: 100)")
    sp.set_defaults(func=_cmd_eql)

    # --- esql ------------------------------------------------------------
    sp = subparsers.add_parser(
        "esql",
        parents=[output_parent],
        help="Execute an ES|QL query",
        epilog=(
            "Examples:\n"
            "  crowdsentinel esql 'FROM logs-* | LIMIT 10'\n"
            "  crowdsentinel esql 'FROM winlogbeat-* | STATS count=COUNT(*) BY host.name' --lean"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sp.add_argument("query", help="ES|QL query string (must start with FROM)")
    sp.add_argument("--no-auto-discover", dest="auto_discover", action="store_false",
                    default=True, help="Disable index auto-discovery")
    sp.add_argument("--lean", action="store_true", default=False,
                    help="Return token-efficient summarised results")
    sp.set_defaults(func=_cmd_esql)

    # --- detect ----------------------------------------------------------
    sp = subparsers.add_parser(
        "detect",
        parents=[output_parent],
        help="Execute a detection rule by ID",
        epilog=(
            "Examples:\n"
            "  crowdsentinel detect windows_powershell_posh_ps_potential_invoke_mimikatz_eql -i winlogbeat-*\n"
            "  crowdsentinel detect my_rule_id -i auditbeat-* --timeframe 60"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sp.add_argument("rule_id", help="Detection rule identifier")
    sp.add_argument("-i", "--index", required=True, help="Index pattern")
    sp.add_argument("--timeframe", type=int, default=15, help="Time window in minutes (default: 15, 0=no filter)")
    sp.add_argument("--size", type=int, default=100, help="Max results (default: 100, max: 1000)")
    sp.set_defaults(func=_cmd_detect)

    # --- rules -----------------------------------------------------------
    sp = subparsers.add_parser(
        "rules",
        parents=[output_parent],
        help="List available detection rules",
        epilog=(
            "Examples:\n"
            "  crowdsentinel rules\n"
            "  crowdsentinel rules --platform windows --log-source powershell\n"
            "  crowdsentinel rules --search mimikatz"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sp.add_argument("--platform", help="Filter by platform (windows, linux, macos, ...)")
    sp.add_argument("--log-source", dest="log_source", help="Filter by log source")
    sp.add_argument("--rule-type", dest="rule_type", choices=["lucene", "eql"], help="Filter by rule type")
    sp.add_argument("--search", help="Search term (name, tags, description)")
    sp.add_argument("--limit", type=int, default=50, help="Max results (default: 50, max: 200)")
    sp.set_defaults(func=_cmd_rules)

    # --- schema ----------------------------------------------------------
    sp = subparsers.add_parser(
        "schema",
        parents=[output_parent],
        help="Detect schema for an index pattern",
        epilog=(
            "Examples:\n"
            "  crowdsentinel schema -i winlogbeat-*\n"
            "  crowdsentinel schema -i logs-endpoint.events.process-*"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sp.add_argument("-i", "--index", required=True, help="Index pattern")
    sp.set_defaults(func=_cmd_schema)

    # --- ioc -------------------------------------------------------------
    sp = subparsers.add_parser(
        "ioc",
        parents=[output_parent],
        help="Hunt for a specific Indicator of Compromise",
        epilog=(
            "Examples:\n"
            "  crowdsentinel ioc 10.0.0.1 --type ip -i winlogbeat-*\n"
            "  crowdsentinel ioc malicious.exe --type filename -i winlogbeat-* --timeframe 1440\n"
            "  crowdsentinel ioc admin --type user -i winlogbeat-*"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sp.add_argument("value", help="IoC value (IP, domain, hash, filename, process, user)")
    sp.add_argument("--type", required=True,
                    choices=["ip", "domain", "hash", "filename", "process", "user"],
                    help="Type of IoC")
    sp.add_argument("-i", "--index", required=True, help="Index pattern")
    sp.add_argument("--timeframe", type=int, default=None,
                    help="Time window in minutes (default: all time)")
    sp.set_defaults(func=_cmd_ioc)

    # --- analyse ---------------------------------------------------------
    sp = subparsers.add_parser(
        "analyse",
        parents=[output_parent],
        help="Analyse search results from stdin (JSON)",
        epilog=(
            "Examples:\n"
            "  cat results.json | crowdsentinel analyse\n"
            "  crowdsentinel hunt 'event.code:4625' -i winlogbeat-* | crowdsentinel analyse --context 'brute force'\n"
            "  echo '{\"hits\":[]}' | crowdsentinel analyse --context 'testing'"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sp.add_argument("--context", "-c", default="",
                    help="Context about what was searched for")
    sp.set_defaults(func=_cmd_analyse)

    # --- pcap ------------------------------------------------------------
    sp = subparsers.add_parser(
        "pcap",
        parents=[output_parent],
        help="Analyse PCAP files for network threats (Wireshark/TShark)",
        epilog=(
            "Examples:\n"
            "  crowdsentinel pcap overview capture.pcap\n"
            "  crowdsentinel pcap beaconing capture.pcap --min-connections 5\n"
            "  crowdsentinel pcap lateral capture.pcap\n"
            "  crowdsentinel pcap sessions capture.pcap --protocol tcp\n"
            "  crowdsentinel pcap iocs capture.pcap --indicators 203.0.113.42 evil.com"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sp.add_argument("action",
                    choices=["overview", "beaconing", "lateral", "sessions", "iocs"],
                    help="Analysis type")
    sp.add_argument("pcap", help="Path to PCAP/PCAPNG file")
    sp.add_argument("--min-connections", type=int, default=10, dest="min_connections",
                    help="Minimum connections for beaconing detection (default: 10)")
    sp.add_argument("--protocol", default="tcp", choices=["tcp", "udp"],
                    help="Protocol for session tracking (default: tcp)")
    sp.add_argument("--indicators", nargs="+",
                    help="IoC values to hunt for (IPs, domains, hashes)")
    sp.set_defaults(func=_cmd_pcap)

    # --- chainsaw --------------------------------------------------------
    sp = subparsers.add_parser(
        "chainsaw",
        parents=[output_parent],
        help="Hunt through EVTX logs with Chainsaw and Sigma rules",
        epilog=(
            "Examples:\n"
            "  crowdsentinel chainsaw hunt /path/to/logs/\n"
            "  crowdsentinel chainsaw hunt /path/to/file.evtx --sigma-rules /path/to/sigma/\n"
            "  crowdsentinel chainsaw search /path/to/logs/ --keyword mimikatz\n"
            "  crowdsentinel chainsaw status"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sp.add_argument("action", choices=["hunt", "search", "status"],
                    help="Chainsaw action")
    sp.add_argument("evtx", nargs="?", default=None,
                    help="Path to EVTX file or directory")
    sp.add_argument("--sigma-rules", dest="sigma_rules", default=None,
                    help="Path to Sigma rules directory")
    sp.add_argument("--mapping", default=None,
                    help="Path to Chainsaw mapping file")
    sp.add_argument("--keyword", default=None,
                    help="Keyword to search for (for 'search' action)")
    sp.set_defaults(func=_cmd_chainsaw)

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    """CLI entry point — parse arguments and dispatch to subcommand."""
    # Graceful Ctrl+C handling
    signal.signal(signal.SIGINT, lambda _sig, _frame: sys.exit(130))

    parser = _build_parser()
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    try:
        exit_code = args.func(args)
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
