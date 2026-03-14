#!/usr/bin/env python3
"""
EQL Search via Elasticsearch Python API.

Execute Event Query Language (EQL) queries against an Elasticsearch cluster.
Supports process hunting, sequence detection, and correlation queries with
configurable output formats for integration into threat hunting pipelines.

Supports both elasticsearch-py v7.x (http_auth) and v8.x (basic_auth).

Exit codes:
    0 - Success (results found)
    1 - Error (connection failure, invalid query, etc.)
    2 - No results matched the query

Usage:
    python eql_search.py --query "process where process.name == 'cmd.exe'"
    python eql_search.py --query "process where process.name == 'powershell.exe'" --index "winlogbeat-*" --size 50
"""

import argparse
import json
import os
import signal
import sys
from typing import Optional, Dict, Any

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

    # Detect elasticsearch-py version
    es_version = int(elasticsearch.__version__[0])

    if api_key:
        return Elasticsearch(
            hosts=hosts.split(","), api_key=api_key, verify_certs=verify_certs
        )
    elif es_version >= 8:
        # v8.x uses basic_auth
        return Elasticsearch(
            hosts=hosts.split(","),
            basic_auth=(username, password),
            verify_certs=verify_certs,
        )
    else:
        # v7.x uses http_auth
        return Elasticsearch(
            hosts=hosts.split(","),
            http_auth=(username, password),
            verify_certs=verify_certs,
        )


def eql_search(
    query: str,
    index: str = "winlogbeat-*",
    size: int = 100,
    timestamp_field: str = "@timestamp",
    filter_query: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Execute an EQL query against Elasticsearch.

    Args:
        query: EQL query string (e.g., 'process where process.name == "cmd.exe"').
        index: Index pattern to search.
        size: Maximum number of results to return.
        timestamp_field: Field containing the event timestamp.
        filter_query: Optional Elasticsearch filter to apply before EQL evaluation.

    Returns:
        EQL search results dictionary from Elasticsearch.
    """
    es = get_es_client()

    body = {"query": query, "size": size, "timestamp_field": timestamp_field}

    if filter_query:
        body["filter"] = filter_query

    print("=== EQL Search ===", file=sys.stderr)
    print(f"Index: {index}", file=sys.stderr)
    print(f"Query: {query}", file=sys.stderr)
    print(f"Size: {size}", file=sys.stderr)
    print("", file=sys.stderr)

    response = es.eql.search(index=index, body=body)

    return response


def _format_table(events, sequences) -> str:
    """Format EQL results as a text table.

    Args:
        events: List of event hits from EQL response.
        sequences: List of sequence hits from EQL response.

    Returns:
        Formatted table string.
    """
    lines = []

    if events:
        col_names = ["#", "Timestamp", "Process", "Host", "User"]
        widths = [4, 26, 40, 20, 20]

        header = " | ".join(name.ljust(widths[i]) for i, name in enumerate(col_names))
        lines.append(header)
        lines.append("-" * len(header))

        for i, event in enumerate(events, 1):
            source = event.get("_source", {})
            timestamp = str(source.get("@timestamp", "N/A"))[:26]
            process_name = (
                source.get("process", {}).get("name")
                or source.get("winlog", {}).get("event_data", {}).get("Image", "N/A")
            )
            host = source.get("host", {}).get("name", "N/A")
            user = (
                source.get("user", {}).get("name")
                or source.get("winlog", {}).get("event_data", {}).get("User", "N/A")
            )

            row = " | ".join(
                [
                    str(i).ljust(widths[0]),
                    str(timestamp).ljust(widths[1]),
                    str(process_name)[:40].ljust(widths[2]),
                    str(host)[:20].ljust(widths[3]),
                    str(user)[:20].ljust(widths[4]),
                ]
            )
            lines.append(row)

    if sequences:
        lines.append("")
        lines.append(f"Sequences: {len(sequences)}")
        for i, seq in enumerate(sequences[:10], 1):
            seq_events = seq.get("events", [])
            lines.append(f"  Sequence {i}: {len(seq_events)} events")
            for j, event in enumerate(seq_events, 1):
                source = event.get("_source", {})
                process_name = (
                    source.get("process", {}).get("name")
                    or source.get("winlog", {})
                    .get("event_data", {})
                    .get("Image", "N/A")
                )
                lines.append(f"    {j}. {process_name}")

    return "\n".join(lines) if lines else "No results"


def main():
    """Entry point for EQL search CLI."""
    parser = argparse.ArgumentParser(
        description="Execute EQL queries against Elasticsearch for threat hunting and detection.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Simple process query
  python eql_search.py --query "process where process.name == 'cmd.exe'"

  # Query with time filter
  python eql_search.py --query "process where process.name == 'powershell.exe'" \\
      --filter '{"range": {"@timestamp": {"gte": "now-1h"}}}'

  # Sequence query (detect cmd.exe spawning network connection)
  python eql_search.py --query "sequence [process where process.name == 'cmd.exe'] \\
      [network where destination.port == 443]"

  # Query specific index with table output
  python eql_search.py --query "process where process.name == 'mimikatz.exe'" \\
      --index "logs-windows.*" --size 50 --output table

Environment Variables:
  ELASTICSEARCH_HOSTS     - Elasticsearch URL (default: http://localhost:9200)
  ELASTICSEARCH_USERNAME  - Username (default: elastic)
  ELASTICSEARCH_PASSWORD  - Password
  ELASTICSEARCH_API_KEY   - API key (alternative to username/password)
  VERIFY_CERTS            - Verify SSL certificates (default: true)

Exit Codes:
  0 - Success (results found)
  1 - Error (connection failure, invalid query, etc.)
  2 - No results matched the query
        """,
    )

    parser.add_argument(
        "--query",
        "-q",
        required=True,
        help="EQL query string (e.g., 'process where process.name == \"cmd.exe\"')",
    )
    parser.add_argument(
        "--index",
        "-i",
        default="winlogbeat-*",
        help="Index pattern to search (default: winlogbeat-*)",
    )
    parser.add_argument(
        "--size",
        "-s",
        type=int,
        default=100,
        help="Maximum number of results (default: 100)",
    )
    parser.add_argument(
        "--timestamp-field",
        "-t",
        default="@timestamp",
        help="Timestamp field name (default: @timestamp)",
    )
    parser.add_argument(
        "--filter", "-f", help="JSON filter query to apply before EQL evaluation"
    )
    parser.add_argument(
        "--output",
        "-o",
        choices=["json", "table", "summary"],
        default="json",
        help="Output format: json (raw), table (columnar), summary (brief) (default: json)",
    )

    args = parser.parse_args()

    _validate_environment()

    filter_query = None
    if args.filter:
        try:
            filter_query = json.loads(args.filter)
        except json.JSONDecodeError as e:
            print(f"Error: Invalid JSON in --filter argument: {e}", file=sys.stderr)
            sys.exit(1)

    try:
        response = eql_search(
            query=args.query,
            index=args.index,
            size=args.size,
            timestamp_field=args.timestamp_field,
            filter_query=filter_query,
        )

        hits = response.get("hits", {})
        total = hits.get("total", {}).get("value", 0)
        events = hits.get("events", [])
        sequences = hits.get("sequences", [])

        if total == 0 and not events and not sequences:
            print("No results matched the query.", file=sys.stderr)
            sys.exit(2)

        if args.output == "json":
            print(json.dumps(response, indent=2, default=str))

        elif args.output == "table":
            print(_format_table(events, sequences))

        else:
            # Summary output
            print(f"\n=== Results Summary ===")
            print(f"Total hits: {total}")

            if events:
                print(f"\nEvents ({len(events)}):")
                for i, event in enumerate(events[:10], 1):
                    source = event.get("_source", {})
                    timestamp = source.get("@timestamp", "N/A")
                    process_name = (
                        source.get("process", {}).get("name")
                        or source.get("winlog", {})
                        .get("event_data", {})
                        .get("Image", "N/A")
                    )
                    print(f"  {i}. [{timestamp}] {process_name}")

                if len(events) > 10:
                    print(f"  ... and {len(events) - 10} more")

            if sequences:
                print(f"\nSequences ({len(sequences)}):")
                for i, seq in enumerate(sequences[:5], 1):
                    seq_events = seq.get("events", [])
                    print(f"  Sequence {i}: {len(seq_events)} events")
                    for j, event in enumerate(seq_events, 1):
                        source = event.get("_source", {})
                        process_name = (
                            source.get("process", {}).get("name")
                            or source.get("winlog", {})
                            .get("event_data", {})
                            .get("Image", "N/A")
                        )
                        print(f"    {j}. {process_name}")

    except Exception as e:
        print(f"Error executing EQL search: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
