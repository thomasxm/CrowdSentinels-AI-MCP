#!/usr/bin/env python3
"""
ES|QL Search via Elasticsearch Python API.

Execute ES|QL (Elasticsearch Query Language) queries for aggregation,
filtering, and data transformation. ES|QL provides a pipe-based query
syntax similar to SPL or KQL, ideal for security analytics and
threat hunting pipelines.

Requires Elasticsearch 8.11 or later and elasticsearch-py 8.x+.

Exit codes:
    0 - Success (results found)
    1 - Error (connection failure, unsupported version, etc.)
    2 - No results matched the query

Usage:
    python esql_search.py --query "FROM logs-* | LIMIT 10"
    python esql_search.py --query "FROM winlogbeat-* | WHERE event.code == '4688' | LIMIT 100"
"""

import argparse
import json
import os
import signal
import sys
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
        return Elasticsearch(hosts=hosts.split(","), api_key=api_key, verify_certs=verify_certs)
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


def check_esql_support(es: Elasticsearch) -> tuple[bool, str]:
    """Check if ES|QL is supported by the connected cluster.

    Validates both the Python library version (requires 8.x+) and
    the Elasticsearch server version (requires 8.11+).

    Args:
        es: Elasticsearch client instance.

    Returns:
        Tuple of (supported: bool, reason: str). Reason is "OK" when supported.
    """
    import elasticsearch

    # Check Python library version first
    lib_version = int(elasticsearch.__version__[0])
    if lib_version < 8:
        return (
            False,
            f"ES|QL requires elasticsearch-py 8.x+ (current: {elasticsearch.__version__})",
        )

    # Check server version
    info = es.info()
    version = info.get("version", {}).get("number", "0.0.0")
    major, minor = map(int, version.split(".")[:2])
    if not (major > 8 or (major == 8 and minor >= 11)):
        return False, f"ES|QL requires Elasticsearch 8.11+ (current: {version})"

    return True, "OK"


def esql_search(query: str) -> dict[str, Any]:
    """Execute an ES|QL query against Elasticsearch.

    Validates ES|QL support before executing the query.

    Args:
        query: ES|QL query string (e.g., 'FROM logs-* | LIMIT 10').

    Returns:
        ES|QL search results with columns and values.

    Raises:
        RuntimeError: If ES|QL is not supported by the cluster or library.
    """
    es = get_es_client()

    # Check version support (both library and server)
    supported, reason = check_esql_support(es)
    if not supported:
        raise RuntimeError(reason)

    print("=== ES|QL Search ===", file=sys.stderr)
    print(f"Query: {query}", file=sys.stderr)
    print("", file=sys.stderr)

    # Execute ES|QL query
    response = es.esql.query(query=query)

    return response


def format_table(columns: list[dict], values: list[list]) -> str:
    """Format ES|QL results as a text table.

    Args:
        columns: List of column definitions from ES|QL response.
        values: List of row value lists from ES|QL response.

    Returns:
        Formatted table string, or "No results" if empty.
    """
    if not columns or not values:
        return "No results"

    # Get column names
    col_names = [col.get("name", "?") for col in columns]

    # Calculate column widths
    widths = [len(name) for name in col_names]
    for row in values[:100]:  # Limit to first 100 rows for width calculation
        for i, val in enumerate(row):
            val_str = str(val) if val is not None else "null"
            widths[i] = max(widths[i], min(len(val_str), 50))  # Cap at 50 chars

    # Build table
    lines = []

    # Header
    header = " | ".join(name.ljust(widths[i]) for i, name in enumerate(col_names))
    lines.append(header)
    lines.append("-" * len(header))

    # Rows
    for row in values:
        row_str = " | ".join(str(val if val is not None else "null")[:50].ljust(widths[i]) for i, val in enumerate(row))
        lines.append(row_str)

    return "\n".join(lines)


def main():
    """Entry point for ES|QL search CLI."""
    parser = argparse.ArgumentParser(
        description="Execute ES|QL queries against Elasticsearch (requires 8.11+).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Simple query
  python esql_search.py --query "FROM logs-* | LIMIT 10"

  # Filter and aggregate
  python esql_search.py --query "FROM winlogbeat-* | WHERE event.code == '4688' | LIMIT 100"

  # Aggregation with stats
  python esql_search.py --query "FROM auditbeat-* | STATS count = COUNT(*) BY process.name | SORT count DESC | LIMIT 20"

  # Table output format
  python esql_search.py --query "FROM logs-* | LIMIT 10" --output table

Environment Variables:
  ELASTICSEARCH_HOSTS     - Elasticsearch URL (default: http://localhost:9200)
  ELASTICSEARCH_USERNAME  - Username (default: elastic)
  ELASTICSEARCH_PASSWORD  - Password
  ELASTICSEARCH_API_KEY   - API key (alternative to username/password)
  VERIFY_CERTS            - Verify SSL certificates (default: true)

Exit Codes:
  0 - Success (results found)
  1 - Error (connection failure, unsupported version, etc.)
  2 - No results matched the query
        """,
    )

    parser.add_argument(
        "--query",
        "-q",
        required=True,
        help="ES|QL query string (e.g., 'FROM logs-* | LIMIT 10')",
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

    try:
        response = esql_search(args.query)

        columns = response.get("columns", [])
        values = response.get("values", [])

        if not values:
            print("No results matched the query.", file=sys.stderr)
            sys.exit(2)

        if args.output == "json":
            print(json.dumps(response, indent=2, default=str))
        elif args.output == "table":
            print(format_table(columns, values))
        else:
            # Summary output
            print("\n=== Results Summary ===")
            print(f"Columns: {', '.join(col.get('name', '?') for col in columns)}")
            print(f"Rows: {len(values)}")

            if values:
                print("\nFirst 5 rows:")
                print(format_table(columns, values[:5]))

                if len(values) > 5:
                    print(f"\n... and {len(values) - 5} more rows")

    except Exception as e:
        print(f"Error executing ES|QL search: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
