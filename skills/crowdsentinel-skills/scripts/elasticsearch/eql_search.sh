#!/bin/bash
# EQL Search via Elasticsearch REST API
#
# Execute Event Query Language (EQL) queries against an Elasticsearch cluster
# using curl. Supports API key and basic authentication.
#
# Exit codes:
#   0 - Success (results found)
#   1 - Error (connection failure, invalid query, etc.)
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
Usage: $0 [OPTIONS] <eql_query> [index] [size]

Execute EQL queries against Elasticsearch via REST API.

Arguments:
  eql_query   EQL query string (required)
  index       Index pattern to search (default: winlogbeat-*)
  size        Maximum number of results (default: 100)

Options:
  -h, --help  Show this help message and exit

Examples:
  $0 'process where process.name == "cmd.exe"'
  $0 'process where process.name == "powershell.exe"' winlogbeat-* 50
  $0 'sequence [process where process.name == "cmd.exe"] [network where destination.port == 443]'

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
INDEX="${2:-winlogbeat-*}"
SIZE="${3:-100}"

if [ -z "$QUERY" ]; then
    echo "Error: EQL query is required." >&2
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

# Build request body
REQUEST_BODY=$(cat <<EOF
{
  "query": "$QUERY",
  "size": $SIZE,
  "timestamp_field": "@timestamp"
}
EOF
)

echo "=== EQL Search ===" >&2
echo "Index: $INDEX" >&2
echo "Query: $QUERY" >&2
echo "Size: $SIZE" >&2
echo "" >&2

# Execute request
if [ -n "$AUTH_HEADER" ]; then
    RESPONSE=$(curl $CURL_OPTS -X POST \
        -H "Content-Type: application/json" \
        -H "$AUTH_HEADER" \
        -d "$REQUEST_BODY" \
        "$ES_HOST/$INDEX/_eql/search")
else
    RESPONSE=$(curl $CURL_OPTS -X POST \
        -H "Content-Type: application/json" \
        -d "$REQUEST_BODY" \
        "$ES_HOST/$INDEX/_eql/search")
fi

# Check for errors in response
if echo "$RESPONSE" | python3 -c "import sys, json; d=json.load(sys.stdin); sys.exit(0 if 'error' not in d else 1)" 2>/dev/null; then
    # Output response
    echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"

    # Extract hit count
    HIT_COUNT=$(echo "$RESPONSE" | python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('hits', {}).get('total', {}).get('value', 0))" 2>/dev/null || echo "0")
    echo "" >&2
    echo "=== Results: $HIT_COUNT hits ===" >&2

    if [ "$HIT_COUNT" = "0" ]; then
        exit 2
    fi
else
    echo "Error executing EQL search:" >&2
    echo "$RESPONSE" | python3 -m json.tool 2>/dev/null >&2 || echo "$RESPONSE" >&2
    exit 1
fi
