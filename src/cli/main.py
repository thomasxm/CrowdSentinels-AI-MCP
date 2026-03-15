"""CrowdSentinel CLI — command-line threat hunting from the terminal.

Provides the same capabilities as the MCP tools, accessible via
the ``crowdsentinel`` command.
"""

import argparse
import json
import os
import signal
import sys
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from src.version import __version__

# ---------------------------------------------------------------------------
# Output formatting helpers
# ---------------------------------------------------------------------------

def _format_json(data: Any) -> str:
    """Return pretty-printed JSON."""
    return json.dumps(data, indent=2, default=str)


def _format_table(data: Any) -> str:
    """Return a human-readable table representation of hunt/search results."""
    if not isinstance(data, dict):
        return _format_json(data)

    lines: list[str] = []

    # --- Analyse output (severity_assessment is the marker) ---
    if "severity_assessment" in data:
        lines.append("=== Analysis ===")
        lines.append(f"  severity: {data['severity_assessment']}")
        if data.get("context"):
            lines.append(f"  context: {data['context']}")
        summary = data.get("summary", {})
        if isinstance(summary, dict):
            for k, v in summary.items():
                lines.append(f"  {k}: {v}")
        lines.append("")

        # MITRE from analyse
        mitre = data.get("mitre_attack_techniques", [])
        if isinstance(mitre, list) and mitre:
            lines.append("=== MITRE ATT&CK ===")
            for t in mitre:
                if isinstance(t, dict):
                    lines.append(f"  {t.get('technique_id','?')} {t.get('technique_name','?')} [{t.get('tactic','?')}] (x{t.get('count','')})")
            lines.append("")

        # IoCs from analyse (piped from hunt)
        piped_iocs = data.get("piped_iocs", {})
        if isinstance(piped_iocs, dict) and piped_iocs:
            lines.append("=== IoCs ===")
            for ioc_type, items in piped_iocs.items():
                if isinstance(items, list):
                    values = [i["value"] if isinstance(i, dict) else str(i) for i in items]
                    lines.append(f"  {ioc_type}: {', '.join(values)}")
            lines.append("")

        # Insights
        raw_insights = data.get("raw_insights", [])
        if isinstance(raw_insights, list) and raw_insights:
            lines.append("=== Insights ===")
            for insight in raw_insights:
                lines.append(f"  - {insight}")
            lines.append("")

        # Recommended follow-up
        followup = data.get("recommended_followup", [])
        if isinstance(followup, list) and followup:
            lines.append("=== Recommended Follow-up ===")
            for f in followup:
                if isinstance(f, dict):
                    lines.append(f"  - {f.get('description', f)}")
                else:
                    lines.append(f"  - {f}")
            lines.append("")

        return "\n".join(lines)

    # --- PCAP overview (packet_count is the marker) ---
    if "packet_count" in data and "protocols" in data:
        lines.append("=== PCAP Overview ===")
        lines.append(f"  file: {data.get('pcap_path', '?')}")
        lines.append(f"  packets: {data.get('packet_count', '?')}")
        lines.append(f"  duration: {data.get('duration_seconds', 0):.0f}s")
        lines.append(f"  size: {data.get('file_size_bytes', 0):,} bytes")
        lines.append(f"  time: {data.get('time_start', '?')} → {data.get('time_end', '?')}")
        lines.append("")

        protocols = data.get("protocols", [])
        if protocols:
            lines.append("=== Top Protocols ===")
            for p in protocols[:10]:
                if isinstance(p, dict):
                    lines.append(f"  {p.get('protocol','?'):15s} pkts={p.get('packet_count',0):>6}  bytes={p.get('byte_count',0):>10}  ({p.get('percentage',0):.1f}%)")
            lines.append("")

        talkers = data.get("top_talkers", [])
        if talkers:
            lines.append("=== Top Talkers ===")
            for t in talkers[:10]:
                if isinstance(t, dict):
                    internal = " [internal]" if t.get("is_internal") else ""
                    lines.append(f"  {t.get('ip','?'):20s} pkts={t.get('packet_count',0):>6}  bytes={t.get('byte_count',0):>10}{internal}")
            lines.append("")

        return "\n".join(lines)

    # --- PCAP beaconing (beacons is the marker) ---
    if "beacons" in data or "patterns" in data:
        summary = data.get("summary", {})
        lines.append("=== Beaconing Analysis ===")
        lines.append(f"  total patterns: {summary.get('total_patterns', 0)}")
        lines.append(f"  high confidence: {summary.get('high_confidence', 0)}")
        lines.append(f"  medium confidence: {summary.get('medium_confidence', 0)}")
        lines.append(f"  low confidence: {summary.get('low_confidence', 0)}")
        lines.append("")

        patterns = data.get("patterns", data.get("beacons", []))
        if patterns:
            lines.append("=== Detected Patterns ===")
            for p in patterns:
                if isinstance(p, dict):
                    lines.append(f"  {p.get('src_ip','?')} → {p.get('dst_ip','?')}:{p.get('dst_port','?')}")
                    lines.append(f"    interval={p.get('interval_mean',0):.0f}s  jitter={p.get('jitter_percent',0):.1f}%  count={p.get('occurrence_count',0)}  confidence={p.get('confidence','?')}")
            lines.append("")

        timeline = data.get("timeline", "")
        if timeline:
            lines.append("=== Timeline ===")
            lines.append(timeline)

        return "\n".join(lines)

    # --- Detect output (rule_info is the marker) ---
    if "rule_info" in data:
        rule = data.get("rule_info", {})
        resp = data.get("response", {})
        lines.append("=== Detection Rule ===")
        lines.append(f"  rule: {rule.get('name', '?')}")
        lines.append(f"  id: {rule.get('rule_id', '?')}")
        lines.append(f"  type: {rule.get('type', '?')}")
        lines.append(f"  tactics: {', '.join(rule.get('mitre_tactics', []))}")
        lines.append(f"  hits: {resp.get('total_hits', 0)}")
        lines.append("")

        subs = data.get("field_substitutions", {})
        if subs.get("count", 0) > 0:
            lines.append(f"  field substitutions: {subs.get('substitutions', {})}")
            lines.append("")

        events = resp.get("events", [])
        if events:
            lines.append(f"=== Events ({len(events)}) ===")
            for evt in events[:10]:
                if isinstance(evt, dict):
                    src = evt.get("_source", evt)
                    ts = src.get("@timestamp", "")
                    msg = src.get("message", "")[:120]
                    lines.append(f"  [{ts}] {msg}")
        else:
            lines.append("  No matching events found.")

        return "\n".join(lines)

    # --- Summary section ---
    summary = data.get("summary", {})
    if isinstance(summary, dict) and summary:
        lines.append("=== Summary ===")
        for k, v in summary.items():
            lines.append(f"  {k}: {v}")
        lines.append("")

    # --- Cluster health (for `crowdsentinel health`) ---
    if "cluster_name" in data:
        lines.append("=== Cluster Health ===")
        for k, v in data.items():
            lines.append(f"  {k}: {v}")
        return "\n".join(lines)

    # --- IoCs ---
    iocs = data.get("iocs", {})
    if isinstance(iocs, dict) and iocs:
        lines.append("=== IoCs ===")
        for ioc_type, items in iocs.items():
            if isinstance(items, list):
                values = [i["value"] if isinstance(i, dict) else str(i) for i in items]
                lines.append(f"  {ioc_type}: {', '.join(values)}")
            else:
                lines.append(f"  {ioc_type}: {items}")
        lines.append("")

    # --- MITRE ATT&CK ---
    mitre = data.get("mitre_techniques", [])
    if isinstance(mitre, list) and mitre:
        lines.append("=== MITRE ATT&CK ===")
        for t in mitre:
            if isinstance(t, dict):
                tid = t.get("technique_id", "?")
                name = t.get("technique_name", "?")
                tactic = t.get("tactic", "?")
                count = t.get("count", "")
                count_str = f" (x{count})" if count else ""
                lines.append(f"  {tid} {name} [{tactic}]{count_str}")
        lines.append("")

    # --- Insights ---
    insights = data.get("insights", [])
    if isinstance(insights, list) and insights:
        lines.append("=== Insights ===")
        for insight in insights:
            lines.append(f"  - {insight}")
        lines.append("")

    # --- Sample events ---
    events = data.get("sample_events", data.get("events", []))
    if isinstance(events, list) and events:
        lines.append(f"=== Sample Events ({len(events)}) ===")
        for evt in events:
            if isinstance(evt, dict):
                ts = evt.get("@timestamp", "")
                host = evt.get("name", evt.get("host.name", ""))
                code = evt.get("code", evt.get("event.code", ""))
                msg = evt.get("message", "")
                if len(msg) > 120:
                    msg = msg[:120] + "..."
                lines.append(f"  [{ts}] host={host} code={code} {msg}")
            else:
                lines.append(f"  {evt}")
        lines.append("")

    # --- Rules (for `crowdsentinel rules`) ---
    rules = data.get("rules", [])
    if isinstance(rules, list) and rules:
        lines.append(f"=== Rules ({data.get('total_matching', data.get('total_found', len(rules)))}) ===")
        for r in rules:
            if isinstance(r, dict):
                rid = r.get("rule_id", "?")
                name = r.get("name", "?")
                rtype = r.get("type", "?")
                tactics = ", ".join(r.get("mitre_tactics", []))
                lines.append(f"  [{rtype}] {name}  ({tactics})")
        lines.append("")

    # --- Pagination ---
    pagination = data.get("pagination", {})
    if isinstance(pagination, dict) and pagination.get("has_more"):
        remaining = pagination.get("guidance", "")
        lines.append(f"  [more results available] {remaining}")

    # --- Workflow hint ---
    hint = data.get("workflow_hint", {})
    if isinstance(hint, dict) and hint.get("next_step"):
        lines.append(f"  Next step: {hint['next_step']} — {hint.get('instruction', '')}")

    # Fallback: if nothing was formatted, dump as key: value
    if not lines:
        for key, value in data.items():
            if isinstance(value, (dict, list)):
                lines.append(f"{key}:")
                lines.append(f"  {_format_json(value)}")
            else:
                lines.append(f"{key}: {value}")

    return "\n".join(lines)


def _format_summary(data: Any) -> str:
    """Return a compact multi-line summary of the most important findings."""
    if not isinstance(data, dict):
        return str(data)

    parts: list[str] = []

    # Extract summary from nested or top-level fields
    summary = data.get("summary", {})
    if isinstance(summary, dict):
        hits = summary.get("total_hits", summary.get("total_events", data.get("total_hits")))
        severity = summary.get("severity", data.get("severity") or data.get("severity_assessment"))
        timeframe = summary.get("timeframe", "")
    else:
        hits = data.get("total_hits", data.get("total_found"))
        severity = data.get("severity") or data.get("severity_assessment")
        timeframe = ""

    # Cluster health
    if "cluster_name" in data:
        status = data.get("status", "?")
        nodes = data.get("number_of_nodes", "?")
        shards = data.get("active_shards", "?")
        unassigned = data.get("unassigned_shards", 0)
        parts.append(f"cluster={data['cluster_name']} status={status} nodes={nodes} shards={shards} unassigned={unassigned}")
        return " | ".join(parts)

    # PCAP overview
    if "packet_count" in data and "protocols" in data:
        parts.append(f"packets={data['packet_count']}")
        parts.append(f"duration={data.get('duration_seconds', 0):.0f}s")
        parts.append(f"protocols={len(data.get('protocols', []))}")
        talkers = data.get("top_talkers", [])
        if talkers:
            top = talkers[0] if isinstance(talkers[0], dict) else {}
            parts.append(f"top_talker={top.get('ip','?')} ({top.get('packet_count',0)} pkts)")
        return "\n".join(parts)

    # PCAP beaconing
    if "beacons" in data or "patterns" in data:
        summary = data.get("summary", {})
        patterns = data.get("patterns", data.get("beacons", []))
        parts.append(f"patterns={summary.get('total_patterns', len(patterns))}")
        parts.append(f"high={summary.get('high_confidence', 0)} medium={summary.get('medium_confidence', 0)} low={summary.get('low_confidence', 0)}")
        for p in patterns[:3]:
            if isinstance(p, dict):
                parts.append(f"{p.get('src_ip','?')} → {p.get('dst_ip','?')}:{p.get('dst_port','?')} interval={p.get('interval_mean',0):.0f}s jitter={p.get('jitter_percent',0):.1f}% ({p.get('confidence','?')})")
        return "\n".join(parts)

    # Detect output
    if "rule_info" in data:
        rule = data.get("rule_info", {})
        resp = data.get("response", {})
        parts.append(f"rule={rule.get('name', '?')}")
        parts.append(f"hits={resp.get('total_hits', 0)}")
        parts.append(f"tactics={','.join(rule.get('mitre_tactics', []))}")
        return "\n".join(parts)

    if hits is not None:
        parts.append(f"hits={hits}")
    if severity:
        parts.append(f"severity={severity}")

    # IoCs count — check both hunt format (iocs) and analyse format (iocs_found, piped_iocs)
    iocs = data.get("iocs") or data.get("piped_iocs", {})
    if isinstance(iocs, dict) and iocs:
        total_iocs = sum(len(v) for v in iocs.values() if isinstance(v, list))
        if total_iocs:
            ioc_types = ", ".join(f"{k}={len(v)}" for k, v in iocs.items() if isinstance(v, list) and v)
            parts.append(f"iocs={total_iocs} ({ioc_types})")
    iocs_found = data.get("iocs_found", [])
    if isinstance(iocs_found, list) and iocs_found:
        parts.append(f"iocs_extracted={len(iocs_found)}")

    # MITRE — check both hunt format (mitre_techniques) and analyse format (mitre_attack_techniques)
    mitre = data.get("mitre_techniques") or data.get("mitre_attack_techniques", [])
    if isinstance(mitre, list) and mitre:
        techniques = [t.get("technique_id", "?") for t in mitre if isinstance(t, dict)]
        parts.append(f"mitre={','.join(techniques)}")

    # Insights — check both hunt format (insights) and analyse format (raw_insights)
    insights = data.get("insights") or data.get("raw_insights", [])
    if isinstance(insights, list) and insights:
        for insight in insights:
            parts.append(insight)

    # Rules count
    rules = data.get("rules", [])
    if isinstance(rules, list) and rules:
        parts.append(f"rules={data.get('total_matching', data.get('total_found', len(rules)))}")

    # Timeframe
    if timeframe:
        parts.append(f"timeframe={timeframe}")

    # Pagination
    pagination = data.get("pagination", {})
    if isinstance(pagination, dict) and pagination.get("has_more"):
        parts.append("has_more=true")

    if not parts:
        # Fallback for unknown data shapes
        for key in ("status", "cluster_name", "total_hits", "total_found",
                     "total", "count", "hits_count", "detected"):
            if key in data:
                parts.append(f"{key}={data[key]}")
        if not parts:
            return " | ".join(f"{k}={v}" for k, v in list(data.items())[:8]
                              if not isinstance(v, (dict, list)))

    return "\n".join(parts)


def _emit(data: Any, output_mode: str) -> None:
    """Write *data* to stdout in the requested format."""
    # Normalise ES client response objects (ObjectApiResponse) to plain dicts
    # so the formatters can inspect keys reliably.
    if hasattr(data, "body"):
        data = data.body
    elif not isinstance(data, (dict, list, str, int, float, bool, type(None))):
        try:
            data = dict(data)
        except (TypeError, ValueError):
            pass

    # If the result is an error dict from the exception handler, raise it
    # so the top-level handler can translate it into an actionable message.
    if isinstance(data, dict) and "error" in data:
        err = str(data["error"])
        if any(s in err for s in ("ConnectionError", "Connection refused",
                                   "TLS error", "SSL", "AuthenticationException",
                                   "AuthorizationException")):
            raise RuntimeError(err)

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


def _get_data_dir() -> Path:
    """Return the writable CrowdSentinel data directory.

    This is where ``crowdsentinel setup`` downloads chainsaw, sigma rules,
    and other mutable data.  Bundled read-only data (detection rules) are
    resolved separately via ``src.paths.get_rules_dir()`` etc.
    """
    import os
    env_dir = os.environ.get("CROWDSENTINEL_DATA_DIR")
    if env_dir:
        return Path(env_dir)

    from src.paths import get_user_data_dir
    return get_user_data_dir()


def _create_rule_loader():
    """Create and load the detection rule loader."""
    from src.clients.common.rule_loader import RuleLoader
    from src.paths import get_rules_dir, get_toml_rules_dir

    rules_dir = get_rules_dir()
    toml_rules_dir = get_toml_rules_dir()

    if rules_dir is None and toml_rules_dir is None:
        print(
            "Error: detection rules not found.\n"
            "Run 'crowdsentinel setup' to download detection rules and Chainsaw.",
            file=sys.stderr,
        )
        return None
    loader = RuleLoader(
        str(rules_dir) if rules_dir else "",
        toml_rules_directory=str(toml_rules_dir) if toml_rules_dir else None,
    )
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

    effective_limit = min(args.limit, 200)

    # Get total matching count (uncapped) then apply limit
    all_matching = loader.search_rules(
        platform=args.platform,
        log_source=args.log_source,
        rule_type=args.rule_type,
        search_term=args.search,
        mitre_tactic=args.tactic,
        limit=999999,
    )
    total_matching = len(all_matching)
    rules = all_matching[:effective_limit]

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
        "total_matching": total_matching,
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
    import os
    data_dir = _get_data_dir()
    chainsaw_dir = data_dir / "chainsaw"

    # Set env vars so ChainsawClient finds the right paths
    if not os.environ.get("CHAINSAW_PATH") and (chainsaw_dir / "chainsaw").exists():
        os.environ["CHAINSAW_PATH"] = str(chainsaw_dir / "chainsaw")
    if not os.environ.get("CHAINSAW_SIGMA_PATH") and (chainsaw_dir / "sigma").exists():
        os.environ["CHAINSAW_SIGMA_PATH"] = str(chainsaw_dir / "sigma")

    from src.clients.common.chainsaw_client import ChainsawClient
    client = ChainsawClient()

    if args.action == "hunt":
        if not args.evtx:
            print("Error: EVTX path required for hunt", file=sys.stderr)
            return 1
        if not client.chainsaw_path.exists():
            print(
                "Error: Chainsaw not installed.\n"
                "Run 'crowdsentinel setup' to download Chainsaw and Sigma rules.",
                file=sys.stderr,
            )
            return 1
        # Resolve mapping path relative to chainsaw binary if not found
        mapping_path = args.mapping
        if not mapping_path and (client.mappings is None or not client.mappings.exists()):
            chainsaw_dir = client.chainsaw_path.parent
            fallback = chainsaw_dir / "mappings" / "sigma-event-logs-all.yml"
            if fallback.exists():
                mapping_path = str(fallback)
        result = client.hunt(
            evtx_path=args.evtx,
            sigma_path=args.sigma_rules,
            mapping_path=mapping_path,
        )
        # Apply --limit to detections
        limit = getattr(args, "limit", 0)
        if limit and isinstance(result, dict):
            detections = result.get("detections", [])
            if len(detections) > limit:
                result["total_detections"] = len(detections)
                result["showing"] = limit
                result["detections"] = detections[:limit]
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
            "sigma_rules_path": str(client.sigma_rules) if client.sigma_rules else "not configured",
            "sigma_rules_exist": client.sigma_rules.exists() if client.sigma_rules else False,
            "data_dir": str(data_dir),
        }
    else:
        print(f"Error: unknown action: {args.action}", file=sys.stderr)
        return 1

    _emit(result, args.output)
    return 0


def _safe_extract_tar(archive_path, dest_dir):
    """Safely extract a tar archive with path traversal protection (CWE-22)."""
    import tarfile
    dest_dir = str(dest_dir)
    # nosemgrep: tarfile-extractall-traversal — members validated via data_filter or manual path check
    with tarfile.open(str(archive_path), "r:gz") as tar:
        if hasattr(tarfile, "data_filter"):
            tar.extractall(path=dest_dir, filter="data")
        else:
            # Fallback for Python < 3.10.12: extract members individually
            # after validating each path to prevent path traversal
            real_dest = os.path.realpath(dest_dir)
            for member in tar.getmembers():
                member_path = os.path.realpath(os.path.join(dest_dir, member.name))
                if not member_path.startswith(real_dest + os.sep) and member_path != real_dest:
                    raise ValueError(f"Path traversal detected in tar member: {member.name!r}")
                tar.extract(member, path=dest_dir)  # nosec B202


def _safe_extract_zip(archive_path, dest_dir):
    """Safely extract a ZIP archive with path traversal protection (CWE-22)."""
    import zipfile
    dest_dir = os.path.realpath(str(dest_dir))
    with zipfile.ZipFile(str(archive_path), "r") as zf:
        for member in zf.namelist():
            target_path = os.path.realpath(os.path.join(dest_dir, member))
            if not target_path.startswith(dest_dir + os.sep) and target_path != dest_dir:
                raise ValueError(f"Path traversal detected in zip member: {member!r}")
        zf.extractall(str(dest_dir))  # nosec B202 - members validated above


def _validate_download_url(url):
    """Validate that a download URL uses the HTTPS scheme only."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(f"Only HTTPS URLs are allowed, got: {parsed.scheme}://")
    return url


def _cmd_auth(args):
    """Manage LLM authentication for agent mode."""
    from src.agent.auth import (
        get_auth_status,
        login_anthropic,
        login_openai,
        remove_auth,
    )

    action = args.action

    if action == "login":
        if args.provider == "openai":
            success = login_openai()
        else:
            success = login_anthropic()
        return 0 if success else 1

    if action == "status":
        status = get_auth_status()
        if status["authenticated"]:
            print("Authenticated: yes")
            print(f"Method: {status['method']}")
            print(f"Provider: {status['provider']}")
            if status.get("expired"):
                print("Token: expired (will auto-refresh on next use)")
            elif status.get("expires_at"):
                remaining = status["expires_at"] - __import__("time").time()
                if remaining > 0:
                    print(f"Expires in: {remaining/3600:.1f} hours")
            if status.get("token_file"):
                print(f"Token file: {status['token_file']}")
        else:
            print("Authenticated: no")
            print("Run: crowdsentinel auth login")
        return 0

    if action == "logout":
        if remove_auth():
            print("Logged out. Stored tokens removed.")
        else:
            print("No stored tokens found.")
        return 0

    return 0


def _cmd_setup(args):
    """Download detection rules and Chainsaw for offline use."""
    import platform
    import urllib.request

    data_dir = _get_data_dir()
    data_dir.mkdir(parents=True, exist_ok=True)

    print(f"CrowdSentinel data directory: {data_dir}")

    # --- Detection Rules ---
    from src.paths import get_rules_dir
    bundled_rules = get_rules_dir()
    rules_dir = data_dir / "rules"
    if bundled_rules is not None:
        rule_count = sum(1 for _ in bundled_rules.rglob("*.eql")) + sum(1 for _ in bundled_rules.rglob("*.lucene"))
        print(f"  Detection rules: bundled with package ({rule_count} rules)")
    elif rules_dir.exists() and any(rules_dir.iterdir()):
        print(f"  Detection rules: already installed ({rules_dir})")
    else:
        print("  Downloading detection rules...")
        rules_dir.mkdir(parents=True, exist_ok=True)
        rules_url = "https://github.com/thomasxm/CrowdSentinel-AI-MCP/releases/download/v0.2.2/detection-rules.tar.gz"
        try:
            rules_archive = data_dir / "detection-rules.tar.gz"
            urllib.request.urlretrieve(_validate_download_url(rules_url), str(rules_archive))
            _safe_extract_tar(rules_archive, data_dir)
            rules_archive.unlink()
            rule_count = sum(1 for _ in rules_dir.rglob("*.eql")) + sum(1 for _ in rules_dir.rglob("*.lucene"))
            print(f"  Detection rules: installed ({rule_count} rules)")
        except Exception as exc:
            print(f"  Detection rules: download failed ({exc})", file=sys.stderr)
            print("  You can manually copy rules/ from the source repository.", file=sys.stderr)

    # --- Chainsaw ---
    chainsaw_dir = data_dir / "chainsaw"
    chainsaw_bin = chainsaw_dir / "chainsaw"
    if chainsaw_bin.exists():
        print(f"  Chainsaw: already installed ({chainsaw_bin})")
    else:
        print("  Downloading Chainsaw...")
        chainsaw_dir.mkdir(parents=True, exist_ok=True)
        arch = platform.machine()
        if arch == "x86_64":
            arch_suffix = "x86_64-unknown-linux-gnu"
        elif arch == "aarch64":
            arch_suffix = "aarch64-unknown-linux-gnu"
        else:
            print(f"  Chainsaw: unsupported architecture ({arch})", file=sys.stderr)
            arch_suffix = None

        if arch_suffix:
            chainsaw_version = "2.13.1"
            chainsaw_url = f"https://github.com/WithSecureLabs/chainsaw/releases/download/v{chainsaw_version}/chainsaw_{arch_suffix}.tar.gz"
            try:
                archive_path = data_dir / "chainsaw.tar.gz"
                urllib.request.urlretrieve(_validate_download_url(chainsaw_url), str(archive_path))
                _safe_extract_tar(archive_path, data_dir)
                archive_path.unlink()
                # Make binary executable
                if chainsaw_bin.exists():
                    chainsaw_bin.chmod(0o755)
                    print(f"  Chainsaw: installed ({chainsaw_bin})")
                else:
                    # Chainsaw extracts into a subdirectory
                    for candidate in chainsaw_dir.rglob("chainsaw"):
                        if candidate.is_file():
                            candidate.chmod(0o755)
                            print(f"  Chainsaw: installed ({candidate})")
                            break
            except Exception as exc:
                print(f"  Chainsaw: download failed ({exc})", file=sys.stderr)

    # --- Sigma Rules for Chainsaw ---
    sigma_dir = chainsaw_dir / "sigma"
    if sigma_dir.exists() and any(sigma_dir.rglob("*.yml")):
        rule_count = sum(1 for _ in sigma_dir.rglob("*.yml"))
        print(f"  Sigma rules: already installed ({rule_count} rules)")
    else:
        print("  Downloading Sigma rules...")
        try:
            sigma_url = "https://github.com/SigmaHQ/sigma/releases/latest/download/sigma_all_rules.zip"
            sigma_archive = data_dir / "sigma_rules.zip"
            urllib.request.urlretrieve(_validate_download_url(sigma_url), str(sigma_archive))
            sigma_dir.mkdir(parents=True, exist_ok=True)
            _safe_extract_zip(sigma_archive, sigma_dir)
            sigma_archive.unlink()
            rule_count = sum(1 for _ in sigma_dir.rglob("*.yml"))
            print(f"  Sigma rules: installed ({rule_count} rules)")
        except Exception as exc:
            print(f"  Sigma rules: download failed ({exc})", file=sys.stderr)

    # --- Mappings for Chainsaw ---
    mappings_dir = chainsaw_dir / "mappings"
    if not mappings_dir.exists():
        mappings_dir.mkdir(parents=True, exist_ok=True)
        mapping_content = """name: Sigma event log sources\nkind: evtx\nrules: sigma\n\ngroups:\n  - name: Sigma\n    timestamp: Event.System.TimeCreated\n    filter:\n      Provider: \"*\"\n    keys:\n      Event.System.Channel: source\n      Event.System.EventID: event_id\n"""
        (mappings_dir / "sigma-event-logs-all.yml").write_text(mapping_content)
        print(f"  Chainsaw mappings: created ({mappings_dir})")

    # --- EVTX Attack Samples (for Chainsaw testing) ---
    evtx_dir = chainsaw_dir / "EVTX-ATTACK-SAMPLES"
    if evtx_dir.exists() and any(evtx_dir.rglob("*.evtx")):
        evtx_count = sum(1 for _ in evtx_dir.rglob("*.evtx"))
        print(f"  EVTX samples: already installed ({evtx_count} files)")
    else:
        print("  Downloading EVTX attack samples...")
        try:
            evtx_url = "https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES/archive/refs/heads/master.zip"
            evtx_archive = data_dir / "evtx-samples.zip"
            urllib.request.urlretrieve(_validate_download_url(evtx_url), str(evtx_archive))
            _safe_extract_zip(evtx_archive, str(chainsaw_dir))
            evtx_archive.unlink()
            # The zip extracts to EVTX-ATTACK-SAMPLES-master — rename
            extracted = chainsaw_dir / "EVTX-ATTACK-SAMPLES-master"
            if extracted.exists() and not evtx_dir.exists():
                extracted.rename(evtx_dir)
            if evtx_dir.exists():
                evtx_count = sum(1 for _ in evtx_dir.rglob("*.evtx"))
                print(f"  EVTX samples: installed ({evtx_count} files)")
            else:
                print("  EVTX samples: extraction completed")
        except Exception as exc:
            print(f"  EVTX samples: download failed ({exc})", file=sys.stderr)
            print("  You can download manually: https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES", file=sys.stderr)

    print(f"\nSetup complete. Data stored in: {data_dir}")
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

    # Agent mode: use AI + MCP tools for investigation
    if getattr(args, "mcp", False):
        return _cmd_analyse_mcp(args, search_results)

    client = _create_client()
    result = client.analyze_search_results(
        search_results=search_results,
        context=args.context or "",
    )
    _emit(result, args.output)
    return 0


def _cmd_analyse_mcp(args, search_results):
    """Run the AI agent investigation loop with MCP tools."""
    from src.agent.config import load_mcp_config
    from src.agent.loop import run_agent
    from src.agent.mcp_bridge import MCPBridge
    from src.agent.providers import create_provider

    # Create LLM provider — auto-login if no auth configured
    try:
        provider = create_provider(
            model=getattr(args, "model", None),
            model_url=getattr(args, "model_url", None),
        )
    except RuntimeError as exc:
        if "No LLM" in str(exc):
            # No auth at all — offer inline login
            print("No LLM authentication found. Starting sign-in...\n", file=sys.stderr)
            from src.agent.auth import login_openai
            if not login_openai():
                print("Authentication failed.", file=sys.stderr)
                return 1
            # Retry after login
            try:
                provider = create_provider(
                    model=getattr(args, "model", None),
                    model_url=getattr(args, "model_url", None),
                )
            except Exception as retry_exc:
                print(f"Agent error after login: {retry_exc}", file=sys.stderr)
                return 1
        else:
            print(f"Agent error: {exc}", file=sys.stderr)
            return 1
    except Exception as exc:
        exc_str = str(exc)
        if "401" in exc_str or "Unauthorized" in exc_str:
            print(
                "LLM API authentication failed. Token may have expired.\n"
                "Run: crowdsentinel auth login\n",
                file=sys.stderr,
            )
        else:
            print(f"Agent error: {exc}", file=sys.stderr)
        return 1

    # Load external MCP server configs
    external_configs = load_mcp_config(
        cli_add=getattr(args, "mcp_server", None),
        cli_exclude=getattr(args, "no_mcp_server", None),
    )

    # Create CrowdSentinel MCP server instance (in-process)
    from src.server import SearchMCPServer
    cs_server = SearchMCPServer(engine_type="elasticsearch")

    # Run agent
    try:
        with MCPBridge(cs_server, external_configs) as bridge:
            result = run_agent(
                provider=provider,
                bridge=bridge,
                hunt_data=search_results,
                context=args.context or "",
                max_steps=getattr(args, "max_steps", 30),
                timeout=getattr(args, "timeout", 300),
            )
    except Exception as exc:
        exc_str = str(exc)
        if "401" in exc_str or "Unauthorized" in exc_str or "AuthenticationException" in exc_str:
            print(
                "LLM API authentication failed.\n"
                "Check your API key:\n"
                '  export ANTHROPIC_API_KEY="sk-ant-..."    # Claude\n'
                '  export OPENAI_API_KEY="sk-..."           # OpenAI\n',
                file=sys.stderr,
            )
        else:
            print(f"Agent error: {exc}", file=sys.stderr)
        return 1

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
    sp.add_argument("--platform", "-p", help="Filter by platform (windows, linux, macos, ...)")
    sp.add_argument("--tactic", help="Filter by MITRE ATT&CK tactic (e.g. credential_access)")
    sp.add_argument("--log-source", dest="log_source", help="Filter by log source")
    sp.add_argument("--rule-type", "--type", "-t", dest="rule_type", choices=["lucene", "eql", "esql"], help="Filter by rule type")
    sp.add_argument("--search", "-s", help="Search term (name, tags, description)")
    sp.add_argument("--limit", "-l", type=int, default=50, help="Max results (default: 50, max: 200)")
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
            "  crowdsentinel hunt 'query' -i idx | crowdsentinel analyse -c 'context'\n"
            "  crowdsentinel hunt 'query' -i idx | crowdsentinel analyse --mcp -c 'context'\n"
            "  crowdsentinel hunt 'query' -i idx | crowdsentinel analyse --mcp --model claude-opus-4-20250514 -c 'deep'\n"
            "  crowdsentinel hunt 'query' -i idx | crowdsentinel analyse --mcp --mcp-server 'vt:uvx virustotal-mcp' -c 'ioc check'"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sp.add_argument("--context", "-c", default="",
                    help="Context about what was searched for")
    # Agent mode flags
    sp.add_argument("--mcp", action="store_true",
                    help="Use AI agent with MCP tools instead of deterministic analysis")
    sp.add_argument("--mcp-server", dest="mcp_server", action="append",
                    help="Add external MCP server (format: name:command args). Repeatable.")
    sp.add_argument("--no-mcp-server", dest="no_mcp_server", action="append",
                    help="Exclude a configured MCP server by name. Repeatable.")
    sp.add_argument("--model", default=None,
                    help="LLM model to use (default: auto-detect from API key)")
    sp.add_argument("--model-url", dest="model_url", default=None,
                    help="OpenAI-compatible API base URL (for Ollama, vLLM, etc.)")
    sp.add_argument("--max-steps", dest="max_steps", type=int, default=30,
                    help="Maximum tool calls before stopping (default: 30)")
    sp.add_argument("--timeout", type=int, default=300,
                    help="Maximum seconds for the agent run (default: 300)")
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
    sp.add_argument("--limit", "-l", type=int, default=0,
                    help="Limit number of detections returned (default: all)")
    sp.set_defaults(func=_cmd_chainsaw)

    # --- setup -----------------------------------------------------------
    sp = subparsers.add_parser(
        "setup",
        help="Download detection rules, Chainsaw, and Sigma rules",
        epilog=(
            "Examples:\n"
            "  crowdsentinel setup\n"
            "  CROWDSENTINEL_DATA_DIR=/opt/crowdsentinel crowdsentinel setup"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sp.set_defaults(func=_cmd_setup)

    # --- auth ------------------------------------------------------------
    sp = subparsers.add_parser(
        "auth",
        help="Manage LLM authentication for agent mode (--mcp)",
        epilog=(
            "Examples:\n"
            "  crowdsentinel auth login                       # OpenAI browser sign-in\n"
            "  crowdsentinel auth login --provider anthropic  # Anthropic sign-in\n"
            "  crowdsentinel auth status                      # Check auth status\n"
            "  crowdsentinel auth logout                      # Remove stored tokens"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sp.add_argument("action", choices=["login", "status", "logout"],
                    help="Auth action to perform")
    sp.add_argument("--provider", choices=["openai", "anthropic"], default="openai",
                    help="LLM provider (default: openai)")
    sp.set_defaults(func=_cmd_auth)

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _handle_cli_error(exc: Exception) -> None:
    """Translate raw exceptions into actionable user messages, then exit."""
    import os

    msg = str(exc)
    hosts = os.environ.get("ELASTICSEARCH_HOSTS", "https://localhost:9200")

    # Connection refused / unreachable
    if "ConnectionError" in type(exc).__name__ or "Connection refused" in msg or "NewConnectionError" in msg:
        print(
            f"Cannot connect to Elasticsearch at {hosts}\n"
            "Check that Elasticsearch is running and ELASTICSEARCH_HOSTS is correct.",
            file=sys.stderr,
        )
        sys.exit(1)

    # TLS / SSL failures
    if "TLS" in msg or "SSL" in msg or "CERTIFICATE_VERIFY_FAILED" in msg:
        print(
            f"TLS/SSL error connecting to {hosts}\n"
            "Possible fixes:\n"
            '  - If Elasticsearch has no TLS:  export ELASTICSEARCH_HOSTS="http://localhost:9200"\n'
            "  - For self-signed certificates: export VERIFY_CERTS=false\n"
            "  - For custom CA:                export VERIFY_CERTS=/path/to/ca.crt",
            file=sys.stderr,
        )
        sys.exit(1)

    # Authentication failures
    if "AuthenticationException" in type(exc).__name__ or "401" in msg:
        print(
            "Authentication failed.\n"
            "Set ELASTICSEARCH_API_KEY or ELASTICSEARCH_USERNAME + ELASTICSEARCH_PASSWORD.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Authorisation failures
    if "AuthorizationException" in type(exc).__name__ or "403" in msg:
        print(
            "Access denied — insufficient permissions.\n"
            "Check the API key or user has the required cluster/index privileges.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Fallback: print the raw error
    print(f"Error: {exc}", file=sys.stderr)
    sys.exit(1)


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
        _handle_cli_error(exc)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
