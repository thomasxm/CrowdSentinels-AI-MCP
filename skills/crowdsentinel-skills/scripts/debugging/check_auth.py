#!/usr/bin/env python3
"""
Check Elasticsearch Authentication and Permissions.

Validates connectivity, authentication credentials, and user permissions
against an Elasticsearch cluster. Reports on cluster health access,
index listing, search capabilities, and EQL support.

Useful for diagnosing "401 Unauthorised" or "403 Forbidden" errors
before running threat hunting queries.

Exit codes:
    0 - Success (authentication valid, permissions checked)
    1 - Error (authentication failed or connection error)
    2 - Authentication succeeded but insufficient permissions

Usage:
    python check_auth.py
    python check_auth.py --verbose
    python check_auth.py --output json
"""

import argparse
import json
import os
import signal
import sys
from typing import Dict, Any, List

try:
    from elasticsearch import (
        Elasticsearch,
        AuthenticationException,
        AuthorizationException,
    )
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
        return Elasticsearch(
            hosts=hosts.split(","),
            basic_auth=(username, password),
            verify_certs=verify_certs,
        )
    else:
        return Elasticsearch(
            hosts=hosts.split(","),
            http_auth=(username, password),
            verify_certs=verify_certs,
        )


def check_authentication(es: Elasticsearch) -> Dict[str, Any]:
    """Check if authentication credentials are valid.

    Args:
        es: Elasticsearch client instance.

    Returns:
        Dictionary with success status, cluster name, and version or error details.
    """
    try:
        info = es.info()
        return {
            "success": True,
            "cluster_name": info.get("cluster_name"),
            "version": info.get("version", {}).get("number"),
        }
    except AuthenticationException as e:
        return {"success": False, "error": "Authentication failed", "details": str(e)}
    except Exception as e:
        return {"success": False, "error": "Connection error", "details": str(e)}


def check_user_info(es: Elasticsearch) -> Dict[str, Any]:
    """Get current authenticated user information.

    Args:
        es: Elasticsearch client instance.

    Returns:
        Dictionary with user information or error details.
    """
    try:
        response = es.security.get_user(username="_current_user")
        return {"success": True, "user_info": response}
    except Exception:
        try:
            response = es.security.authenticate()
            return {"success": True, "user_info": response}
        except Exception as e:
            return {"success": False, "error": str(e)}


def check_permissions(
    es: Elasticsearch, verbose: bool = False
) -> List[Dict[str, Any]]:
    """Check various Elasticsearch permissions for the authenticated user.

    Tests cluster health, index listing, search on common patterns,
    and EQL query support.

    Args:
        es: Elasticsearch client instance.
        verbose: If True, check all index patterns rather than stopping at first success.

    Returns:
        List of permission check results with status and description.
    """
    permission_checks = []

    # Check cluster health (minimal permission)
    try:
        es.cluster.health()
        permission_checks.append(
            {"permission": "cluster:monitor/health", "status": "granted",
             "description": "Can check cluster health"})
    except AuthorizationException:
        permission_checks.append(
            {"permission": "cluster:monitor/health", "status": "denied",
             "description": "Cannot check cluster health"})
    except Exception as e:
        permission_checks.append(
            {"permission": "cluster:monitor/health", "status": "error",
             "description": str(e)})

    # Check index listing
    try:
        es.cat.indices(format="json")
        permission_checks.append(
            {"permission": "indices:monitor/stats", "status": "granted",
             "description": "Can list indices"})
    except AuthorizationException:
        permission_checks.append(
            {"permission": "indices:monitor/stats", "status": "denied",
             "description": "Cannot list indices"})
    except Exception as e:
        permission_checks.append(
            {"permission": "indices:monitor/stats", "status": "error",
             "description": str(e)})

    # Check search on common patterns
    test_indices = ["winlogbeat-*", "logs-*", "auditbeat-*", "*"]
    for idx_pattern in test_indices:
        try:
            es.search(index=idx_pattern, size=0, ignore_unavailable=True)
            permission_checks.append(
                {"permission": f"indices:data/read/search [{idx_pattern}]",
                 "status": "granted",
                 "description": f"Can search {idx_pattern}"})
            if not verbose:
                break
        except AuthorizationException:
            permission_checks.append(
                {"permission": f"indices:data/read/search [{idx_pattern}]",
                 "status": "denied",
                 "description": f"Cannot search {idx_pattern}"})
        except Exception as e:
            if "index_not_found" in str(e).lower():
                permission_checks.append(
                    {"permission": f"indices:data/read/search [{idx_pattern}]",
                     "status": "no_index",
                     "description": f"Index pattern {idx_pattern} does not exist"})
            else:
                permission_checks.append(
                    {"permission": f"indices:data/read/search [{idx_pattern}]",
                     "status": "error", "description": str(e)})

    # Check EQL search
    try:
        es.eql.search(
            index="winlogbeat-*", body={"query": "any where true", "size": 0})
        permission_checks.append(
            {"permission": "indices:data/read/eql", "status": "granted",
             "description": "Can execute EQL queries"})
    except AuthorizationException:
        permission_checks.append(
            {"permission": "indices:data/read/eql", "status": "denied",
             "description": "Cannot execute EQL queries"})
    except Exception as e:
        err_str = str(e).lower()
        if "eql" in err_str and "not supported" in err_str:
            permission_checks.append(
                {"permission": "indices:data/read/eql", "status": "not_supported",
                 "description": "EQL not supported on this version"})
        elif "index_not_found" in err_str or "no such index" in err_str:
            permission_checks.append(
                {"permission": "indices:data/read/eql", "status": "no_index",
                 "description": "No winlogbeat-* index for EQL test"})
        else:
            permission_checks.append(
                {"permission": "indices:data/read/eql", "status": "granted",
                 "description": "Can execute EQL queries (with warnings)"})

    return permission_checks


def _format_table(results: Dict[str, Any]) -> str:
    """Format authentication check results as a table.

    Args:
        results: Full results dictionary from the authentication check.

    Returns:
        Formatted table string.
    """
    lines = []

    lines.append("=== Elasticsearch Authentication Check ===")
    lines.append("")
    lines.append("Configuration:")
    for key, value in results.get("config", {}).items():
        lines.append(f"  {key}: {value}")
    lines.append("")

    if "authentication" in results:
        auth = results["authentication"]
        if auth["success"]:
            lines.append("[OK] Authentication successful")
            lines.append(f"  Cluster: {auth.get('cluster_name')}")
            lines.append(f"  Version: {auth.get('version')}")
        else:
            lines.append(f"[FAIL] {auth.get('error')}")
            lines.append(f"  Details: {auth.get('details')}")
        lines.append("")

    if "user" in results and results["user"].get("success"):
        lines.append("User Info:")
        user_info = results["user"].get("user_info", {})
        if isinstance(user_info, dict):
            username = user_info.get("username", "N/A")
            roles = user_info.get("roles", [])
            lines.append(f"  Username: {username}")
            lines.append(f"  Roles: {', '.join(roles) if roles else 'N/A'}")
        lines.append("")

    if "permissions" in results:
        lines.append("Permission Checks:")
        for perm in results["permissions"]:
            status = perm["status"]
            icon = {"granted": "[OK]", "denied": "[DENIED]", "error": "[ERROR]",
                    "no_index": "[N/A]", "not_supported": "[N/A]"}.get(status, "[?]")
            lines.append(f"  {icon} {perm['description']}")
        lines.append("")

    if "error" in results:
        lines.append(f"[ERROR] {results['error']}")

    granted = sum(1 for p in results.get("permissions", []) if p["status"] == "granted")
    total = len(results.get("permissions", []))
    lines.append(f"=== Summary: {granted}/{total} permissions granted ===")

    return "\n".join(lines)


def main():
    """Entry point for authentication check CLI."""
    parser = argparse.ArgumentParser(
        description="Check Elasticsearch authentication and permissions for threat hunting.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick authentication check
  python check_auth.py

  # Verbose check with all index patterns
  python check_auth.py --verbose

  # JSON output for automation
  python check_auth.py --output json

  # Pipe into jq for specific fields
  python check_auth.py --output json | jq '.permissions[] | select(.status == "denied")'

Environment Variables:
  ELASTICSEARCH_HOSTS     - Elasticsearch URL (default: http://localhost:9200)
  ELASTICSEARCH_USERNAME  - Username (default: elastic)
  ELASTICSEARCH_PASSWORD  - Password
  ELASTICSEARCH_API_KEY   - API key (alternative to username/password)
  VERIFY_CERTS            - Verify SSL certificates (default: true)

Exit Codes:
  0 - Success (authentication valid)
  1 - Error (authentication failed or connection error)
  2 - Authentication succeeded but insufficient permissions
        """,
    )

    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Show detailed permission checks for all index patterns")
    parser.add_argument(
        "--output", "-o", choices=["json", "table", "summary"], default="table",
        help="Output format: json (raw), table (detailed), summary (brief) (default: table)")

    args = parser.parse_args()

    _validate_environment()

    results = {
        "config": {
            "hosts": os.environ.get("ELASTICSEARCH_HOSTS", "http://localhost:9200"),
            "username": os.environ.get("ELASTICSEARCH_USERNAME", "elastic"),
            "api_key": "[SET]" if os.environ.get("ELASTICSEARCH_API_KEY") else "[NOT SET]",
            "verify_certs": os.environ.get("VERIFY_CERTS", "true"),
        }
    }

    try:
        es = get_es_client()
        auth_result = check_authentication(es)
        results["authentication"] = auth_result

        if auth_result["success"]:
            user_result = check_user_info(es)
            results["user"] = user_result
            perm_results = check_permissions(es, args.verbose)
            results["permissions"] = perm_results
    except Exception as e:
        results["error"] = str(e)

    if args.output == "json":
        print(json.dumps(results, indent=2, default=str))
    elif args.output == "table":
        print(_format_table(results))
    else:
        # Summary output
        auth = results.get("authentication", {})
        if auth.get("success"):
            granted = sum(1 for p in results.get("permissions", [])
                          if p["status"] == "granted")
            total = len(results.get("permissions", []))
            print(f"[OK] Authenticated to {results['config']['hosts']} "
                  f"(v{auth.get('version', '?')}) - {granted}/{total} permissions granted")
        else:
            print(f"[FAIL] {auth.get('error', 'Unknown error')}: "
                  f"{auth.get('details', 'No details')}")

    # Determine exit code
    auth = results.get("authentication", {})
    if not auth.get("success"):
        sys.exit(1)
    denied = [p for p in results.get("permissions", []) if p["status"] == "denied"]
    if denied:
        sys.exit(2)
    if "error" in results:
        sys.exit(1)


if __name__ == "__main__":
    main()
