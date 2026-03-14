#!/bin/bash
# Check Elasticsearch Connection
#
# Comprehensive connection diagnostics for Elasticsearch clusters.
# Tests network connectivity, HTTP response, authentication,
# cluster health, and index availability in sequence.
#
# Exit codes:
#   0 - All checks passed
#   1 - Connection or authentication failure

set -e

# Configuration
ES_HOST="${ELASTICSEARCH_HOSTS:-http://localhost:9200}"
ES_USER="${ELASTICSEARCH_USERNAME:-elastic}"
ES_PASS="${ELASTICSEARCH_PASSWORD:-}"
ES_API_KEY="${ELASTICSEARCH_API_KEY:-}"
VERIFY_CERTS="${VERIFY_CERTS:-true}"

usage() {
    cat >&2 <<EOF
Usage: $0 [OPTIONS]

Check Elasticsearch connection with step-by-step diagnostics.

Options:
  -h, --help  Show this help message and exit

Tests performed:
  1. TCP network connectivity
  2. HTTP endpoint response
  3. Cluster information retrieval
  4. Cluster health status
  5. Index count and availability

Environment Variables:
  ELASTICSEARCH_HOSTS     - Elasticsearch URL (default: http://localhost:9200)
  ELASTICSEARCH_USERNAME  - Username (default: elastic)
  ELASTICSEARCH_PASSWORD  - Password
  ELASTICSEARCH_API_KEY   - API key (alternative to username/password)
  VERIFY_CERTS            - Verify SSL certificates (default: true)

Exit Codes:
  0 - All checks passed
  1 - Connection or authentication failure
EOF
    exit "${1:-1}"
}

# Parse options
case "${1:-}" in
    -h|--help)
        usage 0
        ;;
esac

# Validate environment
if [ -z "$ES_API_KEY" ] && [ -z "$ES_PASS" ]; then
    echo "Error: No authentication configured." >&2
    echo "Set ELASTICSEARCH_API_KEY or ELASTICSEARCH_PASSWORD." >&2
    exit 1
fi

echo "=== Elasticsearch Connection Diagnostics ==="
echo ""
echo "Configuration:"
echo "  Host: $ES_HOST"
echo "  User: $ES_USER"
echo "  API Key: ${ES_API_KEY:+[SET]}${ES_API_KEY:-[NOT SET]}"
echo "  Verify Certs: $VERIFY_CERTS"
echo ""

# Build curl options
CURL_OPTS="-s --connect-timeout 10"
if [ "$VERIFY_CERTS" = "false" ]; then
    CURL_OPTS="$CURL_OPTS -k"
fi

# Build authentication
if [ -n "$ES_API_KEY" ]; then
    AUTH_HEADER="Authorization: ApiKey $ES_API_KEY"
    AUTH_METHOD="API Key"
else
    CURL_OPTS="$CURL_OPTS -u $ES_USER:$ES_PASS"
    AUTH_HEADER=""
    AUTH_METHOD="Basic Auth"
fi

echo "=== Step 1: Network Connectivity ==="
echo "Testing TCP connection to $(echo $ES_HOST | sed 's|https\?://||' | cut -d'/' -f1)..."

# Extract host and port
HOST_PORT=$(echo $ES_HOST | sed 's|https\?://||' | cut -d'/' -f1)
HOST=$(echo $HOST_PORT | cut -d':' -f1)
PORT=$(echo $HOST_PORT | grep ':' | cut -d':' -f2)
PORT=${PORT:-9200}

if timeout 5 bash -c "cat < /dev/null > /dev/tcp/$HOST/$PORT" 2>/dev/null; then
    echo "  [OK] TCP connection successful to $HOST:$PORT"
else
    echo "  [FAIL] Cannot connect to $HOST:$PORT" >&2
    echo "" >&2
    echo "  Troubleshooting:" >&2
    echo "    - Check if Elasticsearch is running" >&2
    echo "    - Verify firewall rules" >&2
    echo "    - Confirm ELASTICSEARCH_HOSTS is correct" >&2
    exit 1
fi
echo ""

echo "=== Step 2: HTTP Response ==="
echo "Testing HTTP endpoint..."

if [ -n "$AUTH_HEADER" ]; then
    HTTP_CODE=$(curl $CURL_OPTS -o /dev/null -w "%{http_code}" -H "$AUTH_HEADER" "$ES_HOST" 2>/dev/null || echo "000")
else
    HTTP_CODE=$(curl $CURL_OPTS -o /dev/null -w "%{http_code}" "$ES_HOST" 2>/dev/null || echo "000")
fi

case $HTTP_CODE in
    200)
        echo "  [OK] HTTP 200 - Connection successful"
        ;;
    401)
        echo "  [FAIL] HTTP 401 - Authentication failed" >&2
        echo "" >&2
        echo "  Troubleshooting:" >&2
        echo "    - Check ELASTICSEARCH_USERNAME and ELASTICSEARCH_PASSWORD" >&2
        echo "    - Or check ELASTICSEARCH_API_KEY" >&2
        echo "    - Verify credentials have correct permissions" >&2
        exit 1
        ;;
    403)
        echo "  [FAIL] HTTP 403 - Forbidden" >&2
        echo "" >&2
        echo "  Troubleshooting:" >&2
        echo "    - User authenticated but lacks permissions" >&2
        echo "    - Check role-based access control (RBAC)" >&2
        exit 1
        ;;
    000)
        echo "  [FAIL] No HTTP response (connection timeout or SSL error)" >&2
        echo "" >&2
        echo "  Troubleshooting:" >&2
        echo "    - If using HTTPS, try setting VERIFY_CERTS=false" >&2
        echo "    - Check if ES requires HTTPS vs HTTP" >&2
        exit 1
        ;;
    *)
        echo "  [WARN] HTTP $HTTP_CODE - Unexpected response" >&2
        ;;
esac
echo ""

echo "=== Step 3: Cluster Info ==="
echo "Fetching cluster information..."

if [ -n "$AUTH_HEADER" ]; then
    CLUSTER_INFO=$(curl $CURL_OPTS -H "$AUTH_HEADER" "$ES_HOST" 2>/dev/null)
else
    CLUSTER_INFO=$(curl $CURL_OPTS "$ES_HOST" 2>/dev/null)
fi

if echo "$CLUSTER_INFO" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
    echo "$CLUSTER_INFO" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(f\"  Cluster: {d.get('cluster_name', 'N/A')}\")
print(f\"  Version: {d.get('version', {}).get('number', 'N/A')}\")
print(f\"  Tagline: {d.get('tagline', 'N/A')}\")
"
else
    echo "  [WARN] Could not parse cluster info" >&2
    echo "  Raw response: $CLUSTER_INFO" >&2
fi
echo ""

echo "=== Step 4: Cluster Health ==="
if [ -n "$AUTH_HEADER" ]; then
    HEALTH=$(curl $CURL_OPTS -H "$AUTH_HEADER" "$ES_HOST/_cluster/health" 2>/dev/null)
else
    HEALTH=$(curl $CURL_OPTS "$ES_HOST/_cluster/health" 2>/dev/null)
fi

if echo "$HEALTH" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
    echo "$HEALTH" | python3 -c "
import sys, json
d = json.load(sys.stdin)
status = d.get('status', 'unknown')
status_icon = {'green': '[OK]', 'yellow': '[WARN]', 'red': '[FAIL]'}.get(status, '[?]')
print(f\"  {status_icon} Status: {status}\")
print(f\"  Nodes: {d.get('number_of_nodes', 'N/A')}\")
print(f\"  Data Nodes: {d.get('number_of_data_nodes', 'N/A')}\")
print(f\"  Active Shards: {d.get('active_shards', 'N/A')}\")
"
else
    echo "  [WARN] Could not fetch cluster health" >&2
fi
echo ""

echo "=== Step 5: Index Count ==="
if [ -n "$AUTH_HEADER" ]; then
    INDICES=$(curl $CURL_OPTS -H "$AUTH_HEADER" "$ES_HOST/_cat/indices?format=json" 2>/dev/null)
else
    INDICES=$(curl $CURL_OPTS "$ES_HOST/_cat/indices?format=json" 2>/dev/null)
fi

if echo "$INDICES" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
    echo "$INDICES" | python3 -c "
import sys, json
indices = json.load(sys.stdin)
user_indices = [i for i in indices if not i.get('index', '').startswith('.')]
total_docs = sum(int(i.get('docs.count', 0) or 0) for i in user_indices)
print(f\"  Total indices: {len(user_indices)} (excluding system indices)\")
print(f\"  Total documents: {total_docs:,}\")
if user_indices:
    print(f\"  Sample indices:\")
    for idx in sorted(user_indices, key=lambda x: -int(x.get('docs.count', 0) or 0))[:5]:
        print(f\"    - {idx.get('index')}: {idx.get('docs.count', 0)} docs\")
"
else
    echo "  [WARN] Could not fetch indices" >&2
fi
echo ""

echo "=== Connection Test Complete ==="
echo "All checks passed. Elasticsearch is accessible."
