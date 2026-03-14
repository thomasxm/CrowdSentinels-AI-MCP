#!/bin/bash
# ES|QL Search via Elasticsearch REST API
#
# Execute ES|QL (Elasticsearch Query Language) queries against an
# Elasticsearch cluster using curl. Requires Elasticsearch 8.11 or later.
#
# Exit codes:
#   0 - Success (results found)
#   1 - Error (connection failure, unsupported version, etc.)
#   2 - No results matched the query

set -e

# Configuration - set via environment or defaults
ES_HOST="${ELASTICSEARCH_HOSTS:-http://localhost:9200}"
ES_USER="${ELASTICSEARCH_USERNAME:-elastic}"
ES_PASS="${ELASTICSEARCH_PASSWORD:-}"
ES_API_KEY="${ELASTICSEARCH_API_KEY:-}"
VERIFY_CERTS="${VERIFY_CERTS:-true}"

usage() {
    cat >&2 <<EOF
Usage: $0 [OPTIONS] <esql_query>

Execute ES|QL queries against Elasticsearch via REST API.
Requires Elasticsearch 8.11 or later.

Arguments:
  esql_query  ES|QL query string (required)

Options:
  -h, --help  Show this help message and exit

Examples:
  $0 'FROM logs-* | LIMIT 10'
  $0 'FROM winlogbeat-* | WHERE event.code == "4688" | LIMIT 100'
  $0 'FROM auditbeat-* | STATS count = COUNT(*) BY process.name | SORT count DESC | LIMIT 20'

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
EOF
    exit "${1:-1}"
}

# Parse options
case "${1:-}" in
    -h|--help)
        usage 0
        ;;
esac

# Parse arguments
QUERY="${1:-}"

if [ -z "$QUERY" ]; then
    echo "Error: ES|QL query is required." >&2
    echo "" >&2
    usage 1
fi

# Validate environment
if [ -z "$ES_API_KEY" ] && [ -z "$ES_PASS" ]; then
    echo "Error: No authentication configured." >&2
    echo "Set ELASTICSEARCH_API_KEY or ELASTICSEARCH_PASSWORD." >&2
    exit 1
fi

# Build curl options
CURL_OPTS="-s"
if [ "$VERIFY_CERTS" = "false" ]; then
    CURL_OPTS="$CURL_OPTS -k"
fi

# Build authentication
if [ -n "$ES_API_KEY" ]; then
    AUTH_HEADER="Authorization: ApiKey $ES_API_KEY"
else
    CURL_OPTS="$CURL_OPTS -u $ES_USER:$ES_PASS"
    AUTH_HEADER=""
fi

# Escape query for JSON
ESCAPED_QUERY=$(echo "$QUERY" | python3 -c 'import sys,json; print(json.dumps(sys.stdin.read().strip()))')

# Build request body
REQUEST_BODY="{\"query\": $ESCAPED_QUERY}"

echo "=== ES|QL Search ===" >&2
echo "Query: $QUERY" >&2
echo "" >&2

# Execute request
if [ -n "$AUTH_HEADER" ]; then
    RESPONSE=$(curl $CURL_OPTS -X POST \
        -H "Content-Type: application/json" \
        -H "$AUTH_HEADER" \
        -d "$REQUEST_BODY" \
        "$ES_HOST/_query")
else
    RESPONSE=$(curl $CURL_OPTS -X POST \
        -H "Content-Type: application/json" \
        -d "$REQUEST_BODY" \
        "$ES_HOST/_query")
fi

# Check for ES|QL support
if echo "$RESPONSE" | grep -q "no handler found"; then
    echo "Error: ES|QL not supported. Requires Elasticsearch 8.11 or later." >&2
    exit 1
fi

# Check for errors in response
if echo "$RESPONSE" | python3 -c "import sys, json; d=json.load(sys.stdin); sys.exit(0 if 'error' not in d else 1)" 2>/dev/null; then
    # Output response
    echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"

    # Extract row count
    ROW_COUNT=$(echo "$RESPONSE" | python3 -c "import sys, json; d=json.load(sys.stdin); print(len(d.get('values', [])))" 2>/dev/null || echo "0")
    echo "" >&2
    echo "=== Results: $ROW_COUNT rows ===" >&2

    if [ "$ROW_COUNT" = "0" ]; then
        exit 2
    fi
else
    echo "Error executing ES|QL search:" >&2
    echo "$RESPONSE" | python3 -m json.tool 2>/dev/null >&2 || echo "$RESPONSE" >&2
    exit 1
fi
