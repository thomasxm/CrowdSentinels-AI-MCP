#!/usr/bin/env python3
"""
Detect Data Schema in Elasticsearch Index.

Analyses sample documents from an Elasticsearch index to determine whether
the data uses ECS (Elastic Common Schema), Sysmon (Winlogbeat with Sysmon),
or Windows Security (native Windows event logs). Scoring is based on field
presence, provider names, and ECS version indicators.

This is essential for choosing the correct field names in detection rules
and threat hunting queries.

Exit codes:
    0 - Success (schema detected)
    1 - Error (connection failure, index not found, etc.)
    2 - No documents found in the index

Usage:
    python detect_schema.py --index "winlogbeat-*"
    python detect_schema.py --index "logs-*" --samples 50 --output json
"""

import argparse
import json
import os
import signal
import sys
from collections import defaultdict
from typing import Any

try:
    from elasticsearch import Elasticsearch
except ImportError:
    print("Error: elasticsearch package not installed.", file=sys.stderr)
    print("Install with: pip install elasticsearch", file=sys.stderr)
    sys.exit(1)


def _handle_sigint(signum, frame):
    """Handle Ctrl+C gracefully."""
    print("\nInterrupted by user.", file=sys.stderr)
    sys.exit(130)


signal.signal(signal.SIGINT, _handle_sigint)


def _validate_environment() -> None:
    """Validate required environment variables are set.

    Checks that at least one authentication method (API key or
    username/password) is configured. Prints guidance to stderr
    and exits with code 1 if validation fails.
    """
    hosts = os.environ.get("ELASTICSEARCH_HOSTS")
    api_key = os.environ.get("ELASTICSEARCH_API_KEY")
    password = os.environ.get("ELASTICSEARCH_PASSWORD")

    if not hosts:
        print(
            "Warning: ELASTICSEARCH_HOSTS not set, defaulting to http://localhost:9200",
            file=sys.stderr,
        )

    if not api_key and not password:
        print(
            "Error: No authentication configured. Set either:\n"
            "  ELASTICSEARCH_API_KEY    - API key authentication\n"
            "  ELASTICSEARCH_PASSWORD   - Basic authentication (with ELASTICSEARCH_USERNAME)\n",
            file=sys.stderr,
        )
        sys.exit(1)


# Schema signatures - fields that identify each schema
SCHEMA_SIGNATURES = {
    "sysmon": {
        "required_any": [
            "winlog.event_data.Image",
            "winlog.event_data.OriginalFileName",
            "winlog.event_data.ParentImage",
            "winlog.event_data.TargetFilename",
            "winlog.event_data.SourceIp",
            "winlog.event_data.DestinationIp",
        ],
        "provider_name": "Microsoft-Windows-Sysmon",
        "event_codes": [1, 3, 5, 7, 8, 10, 11, 12, 13, 15, 17, 18, 22, 23],
    },
    "ecs": {
        "required_any": [
            "process.name",
            "process.executable",
            "process.command_line",
            "source.ip",
            "destination.ip",
            "user.name",
            "host.name",
        ],
        "indicator": "ecs.version",
    },
    "windows_security": {
        "required_any": [
            "winlog.event_data.NewProcessName",
            "winlog.event_data.TargetUserName",
            "winlog.event_data.IpAddress",
            "winlog.event_data.LogonType",
        ],
        "provider_name": "Microsoft-Windows-Security-Auditing",
        "event_codes": [4624, 4625, 4648, 4688, 4689, 4697, 4698, 4720, 4732],
    },
}


def get_es_client() -> Elasticsearch:
    """Create Elasticsearch client from environment variables.

    Supports both elasticsearch-py v7.x (http_auth) and v8.x (basic_auth).

    Returns:
        Configured Elasticsearch client instance.
    """
    import elasticsearch

    hosts = os.environ.get("ELASTICSEARCH_HOSTS", "http://localhost:9200")
    api_key = os.environ.get("ELASTICSEARCH_API_KEY")
    username = os.environ.get("ELASTICSEARCH_USERNAME", "elastic")
    password = os.environ.get("ELASTICSEARCH_PASSWORD", "")
    verify_certs = os.environ.get("VERIFY_CERTS", "true").lower() == "true"

    es_version = int(elasticsearch.__version__[0])

    if api_key:
        return Elasticsearch(hosts=hosts.split(","), api_key=api_key, verify_certs=verify_certs)
    elif es_version >= 8:
        return Elasticsearch(hosts=hosts.split(","), basic_auth=(username, password), verify_certs=verify_certs)
    else:
        return Elasticsearch(hosts=hosts.split(","), http_auth=(username, password), verify_certs=verify_certs)


def flatten_dict(d: dict, parent_key: str = "", sep: str = ".") -> dict[str, Any]:
    """Flatten nested dictionary into dot-notation keys."""
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key, v))
    return dict(items)


def get_field_value(doc: dict, field_path: str) -> Any | None:
    """Get value from nested document using dot notation."""
    keys = field_path.split(".")
    value = doc
    for key in keys:
        if isinstance(value, dict):
            value = value.get(key)
        else:
            return None
        if value is None:
            return None
    return value


def detect_schema(index: str, sample_size: int = 20) -> dict[str, Any]:
    """Detect the schema used in an Elasticsearch index.

    Samples documents and scores them against known schema signatures
    (ECS, Sysmon, Windows Security) to determine the data format.

    Args:
        index: Index pattern to analyse.
        sample_size: Number of documents to sample for detection.

    Returns:
        Detection results with schema type, confidence, scores,
        and sample field names.
    """
    es = get_es_client()

    try:
        response = es.search(index=index, query={"match_all": {}}, size=sample_size, ignore_unavailable=True)
    except Exception as e:
        return {"error": f"Failed to search index: {e}"}

    hits = response.get("hits", {}).get("hits", [])
    if not hits:
        return {"error": "No documents found in index", "index": index}

    schema_scores = defaultdict(lambda: {"score": 0, "matches": [], "samples": 0})
    all_fields = set()
    provider_names = set()
    event_codes = set()

    for hit in hits:
        source = hit.get("_source", {})
        flat = flatten_dict(source)
        all_fields.update(flat.keys())

        provider = get_field_value(source, "winlog.provider_name")
        if provider:
            provider_names.add(provider)

        event_code = get_field_value(source, "winlog.event_id") or get_field_value(source, "event.code")
        if event_code:
            try:
                event_codes.add(int(event_code))
            except (ValueError, TypeError):
                pass

        for schema_name, signature in SCHEMA_SIGNATURES.items():
            schema_scores[schema_name]["samples"] += 1
            for field in signature.get("required_any", []):
                if field in flat:
                    schema_scores[schema_name]["score"] += 1
                    if field not in schema_scores[schema_name]["matches"]:
                        schema_scores[schema_name]["matches"].append(field)
            if "provider_name" in signature:
                if provider == signature["provider_name"]:
                    schema_scores[schema_name]["score"] += 5
            if "indicator" in signature:
                if signature["indicator"] in flat:
                    schema_scores[schema_name]["score"] += 10

    best_schema = None
    best_score = 0
    for schema_name, data in schema_scores.items():
        if data["score"] > best_score:
            best_score = data["score"]
            best_schema = schema_name

    total_score = sum(d["score"] for d in schema_scores.values())
    confidence = best_score / total_score if total_score > 0 else 0

    return {
        "detected_schema": best_schema,
        "confidence": round(confidence, 2),
        "scores": dict(schema_scores),
        "providers_found": list(provider_names),
        "event_codes_found": sorted(list(event_codes))[:20],
        "sample_fields": sorted(list(all_fields))[:50],
        "documents_analysed": len(hits),
    }


def main():
    """Entry point for schema detection CLI."""
    parser = argparse.ArgumentParser(
        description="Detect data schema in an Elasticsearch index for correct field mapping.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Detect schema for winlogbeat data
  python detect_schema.py --index "winlogbeat-*"

  # Analyse more samples for higher confidence
  python detect_schema.py --index "logs-windows.*" --samples 50

  # JSON output for automation
  python detect_schema.py --index "auditbeat-*" --output json

  # Pipe into jq for specific fields
  python detect_schema.py --index "winlogbeat-*" -o json | jq '.detected_schema'

Schemas detected:
  - sysmon: Winlogbeat with Sysmon data (winlog.event_data.*)
  - ecs: Elastic Common Schema (process.*, user.*, host.*)
  - windows_security: Native Windows Security events

Environment Variables:
  ELASTICSEARCH_HOSTS     - Elasticsearch URL (default: http://localhost:9200)
  ELASTICSEARCH_USERNAME  - Username (default: elastic)
  ELASTICSEARCH_PASSWORD  - Password
  ELASTICSEARCH_API_KEY   - API key (alternative to username/password)
  VERIFY_CERTS            - Verify SSL certificates (default: true)

Exit Codes:
  0 - Success (schema detected)
  1 - Error (connection failure, index not found, etc.)
  2 - No documents found in the index
        """,
    )

    parser.add_argument("--index", "-i", required=True, help="Index pattern to analyse")
    parser.add_argument(
        "--samples", "-s", type=int, default=20, help="Number of sample documents to analyse (default: 20)"
    )
    parser.add_argument(
        "--output",
        "-o",
        choices=["json", "table", "summary"],
        default="table",
        help="Output format: json (raw), table (detailed), summary (brief) (default: table)",
    )

    args = parser.parse_args()
    _validate_environment()

    result = detect_schema(args.index, args.samples)

    if "error" in result:
        if "No documents found" in result["error"]:
            print(f"No documents found in index: {args.index}", file=sys.stderr)
            sys.exit(2)
        print(f"Error: {result['error']}", file=sys.stderr)
        sys.exit(1)

    if args.output == "json":
        print(json.dumps(result, indent=2, default=str))
    elif args.output == "table":
        print("=== Schema Detection Results ===")
        print()
        print(f"Index: {args.index}")
        print(f"Documents analysed: {result['documents_analysed']}")
        print()
        print(f"Detected Schema: {result['detected_schema']}")
        print(f"Confidence: {result['confidence'] * 100:.0f}%")
        print()
        if result.get("providers_found"):
            print(f"Providers found: {', '.join(result['providers_found'])}")
        if result.get("event_codes_found"):
            codes = result["event_codes_found"]
            print(
                f"Event codes found: {', '.join(map(str, codes[:10]))}"
                + (f" (+{len(codes) - 10} more)" if len(codes) > 10 else "")
            )
        print()
        print("Schema scores:")
        for schema, data in result.get("scores", {}).items():
            indicator = " <<<" if schema == result["detected_schema"] else ""
            print(f"  {schema}: {data['score']} points{indicator}")
            if data.get("matches"):
                print(f"    Matched fields: {', '.join(data['matches'][:5])}")
        print()
        print("Sample fields found:")
        for field in result.get("sample_fields", [])[:15]:
            print(f"  - {field}")
        if len(result.get("sample_fields", [])) > 15:
            print(f"  ... and {len(result['sample_fields']) - 15} more")
    else:
        # Summary output
        schema = result["detected_schema"]
        confidence = result["confidence"] * 100
        doc_count = result["documents_analysed"]
        print(f"[{schema}] Detected with {confidence:.0f}% confidence ({doc_count} documents analysed)")
        if result.get("providers_found"):
            print(f"  Providers: {', '.join(result['providers_found'])}")


if __name__ == "__main__":
    main()
