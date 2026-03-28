#!/usr/bin/env python3
"""
Transform EQL/Lucene Queries Between Elasticsearch Schemas.

Converts queries written for one field schema (e.g., ECS) to equivalent
queries for another schema (e.g., Sysmon or Windows Security). Supports
both EQL and Lucene query syntax with automatic type detection.

Essential when detection rules use ECS field names but your data uses
raw winlogbeat fields, or vice versa.

Exit codes:
    0 - Success (query transformed)
    1 - Error (no translation available, invalid arguments)
    2 - No field replacements needed (query already matches target schema)

Usage:
    python transform_query.py --query "process where process.name == 'cmd.exe'" --from ecs --to sysmon
    python transform_query.py --query "process.name:powershell*" --from ecs --to sysmon --type lucene
"""

import argparse
import json
import re
import signal
import sys

# Field mappings between schemas (ECS, Sysmon, Windows Security)
FIELD_MAPPINGS = {
    "process.name": {
        "ecs": "process.name",
        "sysmon": "winlog.event_data.Image",
        "windows_security": "winlog.event_data.NewProcessName",
    },
    "process.executable": {
        "ecs": "process.executable",
        "sysmon": "winlog.event_data.Image",
        "windows_security": "winlog.event_data.NewProcessName",
    },
    "process.command_line": {
        "ecs": "process.command_line",
        "sysmon": "winlog.event_data.CommandLine",
        "windows_security": "winlog.event_data.CommandLine",
    },
    "process.pid": {
        "ecs": "process.pid",
        "sysmon": "winlog.event_data.ProcessId",
        "windows_security": "winlog.event_data.NewProcessId",
    },
    "process.parent.name": {
        "ecs": "process.parent.name",
        "sysmon": "winlog.event_data.ParentImage",
        "windows_security": "winlog.event_data.ParentProcessName",
    },
    "process.parent.pid": {
        "ecs": "process.parent.pid",
        "sysmon": "winlog.event_data.ParentProcessId",
        "windows_security": "winlog.event_data.ProcessId",
    },
    "process.parent.command_line": {
        "ecs": "process.parent.command_line",
        "sysmon": "winlog.event_data.ParentCommandLine",
        "windows_security": None,
    },
    "user.name": {
        "ecs": "user.name",
        "sysmon": "winlog.event_data.User",
        "windows_security": "winlog.event_data.TargetUserName",
    },
    "user.domain": {"ecs": "user.domain", "sysmon": None, "windows_security": "winlog.event_data.TargetDomainName"},
    "source.ip": {
        "ecs": "source.ip",
        "sysmon": "winlog.event_data.SourceIp",
        "windows_security": "winlog.event_data.IpAddress",
    },
    "source.port": {
        "ecs": "source.port",
        "sysmon": "winlog.event_data.SourcePort",
        "windows_security": "winlog.event_data.IpPort",
    },
    "destination.ip": {"ecs": "destination.ip", "sysmon": "winlog.event_data.DestinationIp", "windows_security": None},
    "destination.port": {
        "ecs": "destination.port",
        "sysmon": "winlog.event_data.DestinationPort",
        "windows_security": None,
    },
    "dns.question.name": {
        "ecs": "dns.question.name",
        "sysmon": "winlog.event_data.QueryName",
        "windows_security": None,
    },
    "file.path": {
        "ecs": "file.path",
        "sysmon": "winlog.event_data.TargetFilename",
        "windows_security": "winlog.event_data.ObjectName",
    },
    "file.name": {
        "ecs": "file.name",
        "sysmon": "winlog.event_data.TargetFilename",
        "windows_security": "winlog.event_data.ObjectName",
    },
    "registry.path": {
        "ecs": "registry.path",
        "sysmon": "winlog.event_data.TargetObject",
        "windows_security": "winlog.event_data.ObjectName",
    },
    "registry.value": {"ecs": "registry.value", "sysmon": "winlog.event_data.Details", "windows_security": None},
    "host.name": {"ecs": "host.name", "sysmon": "host.name", "windows_security": "winlog.computer_name"},
    "event.code": {"ecs": "event.code", "sysmon": "winlog.event_id", "windows_security": "winlog.event_id"},
}


def _handle_sigint(signum, frame):
    """Handle Ctrl+C gracefully."""
    print("\nInterrupted by user.", file=sys.stderr)
    sys.exit(130)


signal.signal(signal.SIGINT, _handle_sigint)


def build_translation_table(from_schema: str, to_schema: str) -> dict[str, str]:
    """Build a translation table from one schema to another."""
    table = {}
    for ecs_field, mappings in FIELD_MAPPINGS.items():
        from_field = mappings.get(from_schema)
        to_field = mappings.get(to_schema)
        if from_field and to_field:
            table[from_field] = to_field
    return table


def transform_eql_query(query: str, translation_table: dict[str, str]) -> dict:
    """Transform an EQL query using the translation table.

    Replaces field names using word-boundary matching, processing
    longer field names first to avoid partial replacements.
    """
    transformed = query
    replacements = []
    sorted_fields = sorted(translation_table.keys(), key=len, reverse=True)

    for from_field in sorted_fields:
        to_field = translation_table[from_field]
        pattern = rf"\b{re.escape(from_field)}\b"
        if re.search(pattern, transformed):
            transformed = re.sub(pattern, to_field, transformed)
            replacements.append({"from": from_field, "to": to_field})

    return {"original": query, "transformed": transformed, "replacements": replacements, "query_type": "eql"}


def transform_lucene_query(query: str, translation_table: dict[str, str]) -> dict:
    """Transform a Lucene query using the translation table.

    Replaces field:value patterns, processing longer field names first.
    """
    transformed = query
    replacements = []
    sorted_fields = sorted(translation_table.keys(), key=len, reverse=True)

    for from_field in sorted_fields:
        to_field = translation_table[from_field]
        pattern = rf"\b{re.escape(from_field)}:"
        if re.search(pattern, transformed):
            transformed = re.sub(pattern, f"{to_field}:", transformed)
            replacements.append({"from": from_field, "to": to_field})

    return {"original": query, "transformed": transformed, "replacements": replacements, "query_type": "lucene"}


def transform_query(query: str, from_schema: str, to_schema: str, query_type: str = "auto") -> dict:
    """Transform a query from one schema to another.

    Supports EQL and Lucene query syntax with automatic type detection
    based on EQL keywords and comparison operators.

    Args:
        query: The query string to transform.
        from_schema: Source schema (ecs, sysmon, windows_security).
        to_schema: Target schema.
        query_type: Query type (eql, lucene, or auto for auto-detect).

    Returns:
        Transformation result with original and transformed queries.
    """
    if query_type == "auto":
        if " where " in query.lower() or re.search(r"\s+(==|!=|>=|<=|>|<)\s+", query):
            query_type = "eql"
        else:
            query_type = "lucene"

    translation_table = build_translation_table(from_schema, to_schema)
    if not translation_table:
        return {"error": f"No translation available from {from_schema} to {to_schema}", "original": query}

    if query_type == "eql":
        return transform_eql_query(query, translation_table)
    else:
        return transform_lucene_query(query, translation_table)


def main():
    """Entry point for query transformation CLI."""
    parser = argparse.ArgumentParser(
        description="Transform EQL/Lucene queries between Elasticsearch schemas.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Transform EQL query from ECS to Sysmon
  python transform_query.py \\
      --query "process where process.name == 'cmd.exe' and process.parent.name == 'explorer.exe'" \\
      --from ecs --to sysmon

  # Transform Lucene query
  python transform_query.py \\
      --query "process.name:powershell* AND process.command_line:*encoded*" \\
      --from ecs --to sysmon --type lucene

  # Transform from Sysmon to ECS
  python transform_query.py \\
      --query 'winlog.event_data.Image:*mimikatz*' \\
      --from sysmon --to ecs

  # JSON output for automation
  python transform_query.py --query "process where process.name == 'cmd.exe'" \\
      --from ecs --to sysmon --output json

Supported schemas:
  - ecs: Elastic Common Schema
  - sysmon: Winlogbeat with Sysmon
  - windows_security: Native Windows Security events

Exit Codes:
  0 - Success (query transformed with field replacements)
  1 - Error (no translation available)
  2 - No field replacements needed (fields already match target schema)
        """,
    )

    parser.add_argument("--query", "-q", required=True, help="Query string to transform")
    parser.add_argument(
        "--from", dest="from_schema", required=True, choices=["ecs", "sysmon", "windows_security"], help="Source schema"
    )
    parser.add_argument(
        "--to", dest="to_schema", required=True, choices=["ecs", "sysmon", "windows_security"], help="Target schema"
    )
    parser.add_argument(
        "--type", "-t", choices=["eql", "lucene", "auto"], default="auto", help="Query type (default: auto-detect)"
    )
    parser.add_argument(
        "--output",
        "-o",
        choices=["json", "table", "summary"],
        default="table",
        help="Output format: json (raw), table (detailed), summary (brief) (default: table)",
    )

    args = parser.parse_args()

    result = transform_query(args.query, args.from_schema, args.to_schema, args.type)

    if "error" in result:
        print(f"Error: {result['error']}", file=sys.stderr)
        sys.exit(1)

    if not result.get("replacements"):
        if args.output == "json":
            print(json.dumps(result, indent=2))
        elif args.output == "summary":
            print(result["transformed"])
        else:
            print("No field replacements needed (fields already match target schema)", file=sys.stderr)
            print(result["transformed"])
        sys.exit(2)

    if args.output == "json":
        print(json.dumps(result, indent=2))
    elif args.output == "summary":
        print(result["transformed"])
    else:
        print("=== Query Transformation ===")
        print()
        print(f"From: {args.from_schema}")
        print(f"To: {args.to_schema}")
        print(f"Type: {result.get('query_type', 'unknown')}")
        print()
        print("Original query:")
        print(f"  {result['original']}")
        print()
        print("Transformed query:")
        print(f"  {result['transformed']}")
        print()
        if result.get("replacements"):
            print("Field replacements:")
            for r in result["replacements"]:
                print(f"  {r['from']} -> {r['to']}")


if __name__ == "__main__":
    main()
