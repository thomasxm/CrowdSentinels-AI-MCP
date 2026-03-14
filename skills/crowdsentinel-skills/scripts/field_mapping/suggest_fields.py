#!/usr/bin/env python3
"""
Suggest Field Mappings Across Elasticsearch Schemas.

Given an ECS field name (or a native field name), suggests equivalent fields
in other schemas (Sysmon, Windows Security). Invaluable when detection rules
fail due to field name mismatches between ECS and raw winlogbeat data.

Also provides fuzzy matching for partial field names and a comprehensive
listing of all known field mappings.

Exit codes:
    0 - Success (mapping found)
    1 - Error (field not found in mapping table)
    2 - No similar fields found

Usage:
    python suggest_fields.py --field "process.name"
    python suggest_fields.py --field "source.ip" --schema sysmon
    python suggest_fields.py --list
"""

import argparse
import json
import signal
import sys
from typing import Dict, List, Optional


def _handle_sigint(signum, frame):
    """Handle Ctrl+C gracefully."""
    print("\nInterrupted by user.", file=sys.stderr)
    sys.exit(130)


signal.signal(signal.SIGINT, _handle_sigint)


# Comprehensive field mapping table
FIELD_MAPPINGS = {
    "process.name": {
        "ecs": "process.name", "sysmon": "winlog.event_data.Image",
        "windows_security": "winlog.event_data.NewProcessName",
        "description": "Process executable name/path",
        "event_types": ["process_create", "process_terminate"]},
    "process.executable": {
        "ecs": "process.executable", "sysmon": "winlog.event_data.Image",
        "windows_security": "winlog.event_data.NewProcessName",
        "description": "Full path to process executable"},
    "process.command_line": {
        "ecs": "process.command_line", "sysmon": "winlog.event_data.CommandLine",
        "windows_security": "winlog.event_data.CommandLine",
        "description": "Process command line arguments"},
    "process.pid": {
        "ecs": "process.pid", "sysmon": "winlog.event_data.ProcessId",
        "windows_security": "winlog.event_data.NewProcessId",
        "description": "Process ID"},
    "process.parent.name": {
        "ecs": "process.parent.name", "sysmon": "winlog.event_data.ParentImage",
        "windows_security": "winlog.event_data.ParentProcessName",
        "description": "Parent process name/path"},
    "process.parent.pid": {
        "ecs": "process.parent.pid", "sysmon": "winlog.event_data.ParentProcessId",
        "windows_security": "winlog.event_data.ProcessId",
        "description": "Parent process ID"},
    "process.parent.command_line": {
        "ecs": "process.parent.command_line",
        "sysmon": "winlog.event_data.ParentCommandLine",
        "windows_security": None, "description": "Parent process command line"},
    "process.hash.sha256": {
        "ecs": "process.hash.sha256", "sysmon": "winlog.event_data.Hashes",
        "windows_security": None, "description": "Process file SHA256 hash"},
    "user.name": {
        "ecs": "user.name", "sysmon": "winlog.event_data.User",
        "windows_security": "winlog.event_data.TargetUserName",
        "description": "Username"},
    "user.domain": {
        "ecs": "user.domain", "sysmon": None,
        "windows_security": "winlog.event_data.TargetDomainName",
        "description": "User domain"},
    "user.id": {
        "ecs": "user.id", "sysmon": None,
        "windows_security": "winlog.event_data.TargetUserSid",
        "description": "User SID"},
    "source.ip": {
        "ecs": "source.ip", "sysmon": "winlog.event_data.SourceIp",
        "windows_security": "winlog.event_data.IpAddress",
        "description": "Source IP address",
        "event_types": ["network_connection", "logon"]},
    "source.port": {
        "ecs": "source.port", "sysmon": "winlog.event_data.SourcePort",
        "windows_security": "winlog.event_data.IpPort",
        "description": "Source port"},
    "destination.ip": {
        "ecs": "destination.ip", "sysmon": "winlog.event_data.DestinationIp",
        "windows_security": None, "description": "Destination IP address"},
    "destination.port": {
        "ecs": "destination.port", "sysmon": "winlog.event_data.DestinationPort",
        "windows_security": None, "description": "Destination port"},
    "dns.question.name": {
        "ecs": "dns.question.name", "sysmon": "winlog.event_data.QueryName",
        "windows_security": None, "description": "DNS query domain name",
        "event_types": ["dns_query"]},
    "file.path": {
        "ecs": "file.path", "sysmon": "winlog.event_data.TargetFilename",
        "windows_security": "winlog.event_data.ObjectName",
        "description": "File path",
        "event_types": ["file_create", "file_modify"]},
    "file.name": {
        "ecs": "file.name", "sysmon": "winlog.event_data.TargetFilename",
        "windows_security": "winlog.event_data.ObjectName",
        "description": "File name"},
    "file.hash.sha256": {
        "ecs": "file.hash.sha256", "sysmon": "winlog.event_data.Hash",
        "windows_security": None, "description": "File SHA256 hash"},
    "registry.path": {
        "ecs": "registry.path", "sysmon": "winlog.event_data.TargetObject",
        "windows_security": "winlog.event_data.ObjectName",
        "description": "Registry key path",
        "event_types": ["registry_modify"]},
    "registry.value": {
        "ecs": "registry.value", "sysmon": "winlog.event_data.Details",
        "windows_security": None, "description": "Registry value"},
    "host.name": {
        "ecs": "host.name", "sysmon": "host.name",
        "windows_security": "winlog.computer_name",
        "description": "Hostname"},
    "host.hostname": {
        "ecs": "host.hostname", "sysmon": "host.hostname",
        "windows_security": "winlog.computer_name",
        "description": "Hostname (alternative)"},
    "event.code": {
        "ecs": "event.code", "sysmon": "winlog.event_id",
        "windows_security": "winlog.event_id",
        "description": "Event ID"},
    "event.action": {
        "ecs": "event.action", "sysmon": "winlog.event_data.RuleName",
        "windows_security": None, "description": "Event action/rule name"},
}

# Reverse mapping for finding ECS equivalent from native field names
REVERSE_MAPPINGS: Dict[str, str] = {}
for ecs_field, mappings in FIELD_MAPPINGS.items():
    for schema, field in mappings.items():
        if schema in ["ecs", "sysmon", "windows_security"] and field:
            REVERSE_MAPPINGS[field.lower()] = ecs_field


def suggest_field(field: str, target_schema: Optional[str] = None) -> Dict:
    """Suggest equivalent fields across schemas.

    Looks up a field name (ECS or native) and returns its equivalents
    in all supported schemas. Supports fuzzy matching for partial names.

    Args:
        field: Field name to look up (ECS or native format).
        target_schema: Optional specific schema to highlight in results.

    Returns:
        Mapping suggestions dictionary with alternatives and descriptions.
    """
    field_lower = field.lower()

    # Check if it's an ECS field
    if field_lower in [k.lower() for k in FIELD_MAPPINGS.keys()]:
        for key in FIELD_MAPPINGS:
            if key.lower() == field_lower:
                mapping = FIELD_MAPPINGS[key]
                result = {
                    "input_field": field, "is_ecs": True,
                    "description": mapping.get("description"),
                    "mappings": {
                        "ecs": mapping.get("ecs"),
                        "sysmon": mapping.get("sysmon"),
                        "windows_security": mapping.get("windows_security")}}
                if target_schema:
                    result["suggested_field"] = mapping.get(target_schema)
                return result

    # Check if it's a native field (reverse lookup)
    if field_lower in REVERSE_MAPPINGS:
        ecs_field = REVERSE_MAPPINGS[field_lower]
        mapping = FIELD_MAPPINGS[ecs_field]
        return {
            "input_field": field, "is_ecs": False,
            "ecs_equivalent": ecs_field,
            "description": mapping.get("description"),
            "mappings": {
                "ecs": mapping.get("ecs"),
                "sysmon": mapping.get("sysmon"),
                "windows_security": mapping.get("windows_security")}}

    # Fuzzy match - find similar fields
    suggestions = []
    for key in FIELD_MAPPINGS:
        if any(part in key.lower() for part in field_lower.split(".")):
            suggestions.append(key)

    return {
        "input_field": field, "found": False,
        "message": "Field not found in mapping table",
        "similar_fields": suggestions[:5],
        "hint": "Try using detect_schema.py to find actual field names in your data"}


def list_all_mappings() -> List[Dict]:
    """List all available field mappings."""
    result = []
    for ecs_field, mapping in FIELD_MAPPINGS.items():
        result.append({
            "ecs_field": ecs_field,
            "sysmon": mapping.get("sysmon"),
            "windows_security": mapping.get("windows_security"),
            "description": mapping.get("description")})
    return result


def main():
    """Entry point for field suggestion CLI."""
    parser = argparse.ArgumentParser(
        description="Suggest field mappings across Elasticsearch schemas for threat hunting.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Get all mappings for an ECS field
  python suggest_fields.py --field "process.name"

  # Get specific schema mapping
  python suggest_fields.py --field "process.command_line" --schema sysmon

  # Look up a native field to find ECS equivalent
  python suggest_fields.py --field "winlog.event_data.Image"

  # List all available mappings
  python suggest_fields.py --list

  # JSON output for automation
  python suggest_fields.py --field "source.ip" --output json

Supported schemas:
  - ecs: Elastic Common Schema
  - sysmon: Winlogbeat with Sysmon
  - windows_security: Native Windows Security events

Exit Codes:
  0 - Success (mapping found or list displayed)
  1 - Error (field not found in mapping table)
  2 - No similar fields found
        """,
    )

    parser.add_argument("--field", "-f", help="Field name to look up")
    parser.add_argument("--schema", "-s", choices=["ecs", "sysmon", "windows_security"],
                        help="Target schema for suggestion")
    parser.add_argument("--list", "-l", action="store_true", help="List all field mappings")
    parser.add_argument("--output", "-o", choices=["json", "table", "summary"],
                        default="table",
                        help="Output format: json (raw), table (detailed), summary (brief) (default: table)")

    args = parser.parse_args()

    if args.list:
        mappings = list_all_mappings()
        if args.output == "json":
            print(json.dumps(mappings, indent=2))
        elif args.output == "summary":
            for m in mappings:
                print(f"  {m['ecs_field']} -> {m['sysmon'] or 'N/A'}")
        else:
            print("=== Available Field Mappings ===")
            print()
            print(f"{'ECS Field':<30} {'Sysmon':<40} {'Win Security':<35}")
            print("-" * 105)
            for m in mappings:
                ecs = m["ecs_field"][:30]
                sysmon = (m["sysmon"] or "N/A")[:40]
                winsec = (m["windows_security"] or "N/A")[:35]
                print(f"{ecs:<30} {sysmon:<40} {winsec:<35}")
        return

    if not args.field:
        parser.print_help()
        sys.exit(1)

    result = suggest_field(args.field, args.schema)

    if args.output == "json":
        print(json.dumps(result, indent=2))
    elif args.output == "summary":
        if result.get("found") is False:
            print(f"Not found: {result['input_field']}", file=sys.stderr)
            if result.get("similar_fields"):
                print(f"  Similar: {', '.join(result['similar_fields'])}", file=sys.stderr)
            sys.exit(1)
        mappings = result.get("mappings", {})
        for schema, field in mappings.items():
            if field:
                print(f"  {schema}: {field}")
    else:
        # Table output
        print("=== Field Mapping Suggestion ===")
        print()
        print(f"Input: {result['input_field']}")

        if result.get("found") is False:
            print(f"Status: {result['message']}", file=sys.stderr)
            if result.get("similar_fields"):
                print(f"Similar fields: {', '.join(result['similar_fields'])}", file=sys.stderr)
            else:
                sys.exit(2)
            if result.get("hint"):
                print(f"Hint: {result['hint']}", file=sys.stderr)
            sys.exit(1)

        if result.get("description"):
            print(f"Description: {result['description']}")
        if result.get("is_ecs"):
            print("Type: ECS field")
        else:
            print(f"Type: Native field (ECS equivalent: {result.get('ecs_equivalent')})")

        print()
        print("Mappings:")
        for schema, field in result.get("mappings", {}).items():
            indicator = " <<<" if args.schema and schema == args.schema else ""
            field_str = field if field else "N/A"
            print(f"  {schema:<20}: {field_str}{indicator}")

        if args.schema and result.get("suggested_field"):
            print()
            print(f"Suggested field for {args.schema}: {result['suggested_field']}")


if __name__ == "__main__":
    main()
