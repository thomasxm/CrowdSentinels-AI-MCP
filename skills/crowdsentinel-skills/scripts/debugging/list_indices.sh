#!/bin/bash
# List Elasticsearch Indices with Details
#
# Displays all user-facing indices with document counts, sizes, and
# health status. Also groups indices by pattern and shows common
# index patterns for use in queries.
#
# Exit codes:
#   0 - Success (indices listed)
#   1 - Error (connection failure, authentication error)
#   2 - No indices found matching the pattern

set -e

# Configuration
ES_HOST="${ELASTICSEARCH_HOSTS:-http://localhost:9200}"
ES_USER="${ELASTICSEARCH_USERNAME:-elastic}"
ES_PASS="${ELASTICSEARCH_PASSWORD:-}"
ES_API_KEY="${ELASTICSEARCH_API_KEY:-}"
VERIFY_CERTS="${VERIFY_CERTS:-true}"

usage() {
    cat >&2 <<EOF
Usage: $0 [OPTIONS] [pattern]

List Elasticsearch indices with document counts and health status.

Arguments:
  pattern     Optional regex pattern to filter indices (case-insensitive)

Options:
  -h, --help  Show this help message and exit

Examples:
  $0                  # List all indices
  $0 winlogbeat       # Filter to winlogbeat indices
  $0 'logs-.*'        # Filter with regex pattern

Environment Variables:
  ELASTICSEARCH_HOSTS     - Elasticsearch URL (default: http://localhost:9200)
  ELASTICSEARCH_USERNAME  - Username (default: elastic)
  ELASTICSEARCH_PASSWORD  - Password
  ELASTICSEARCH_API_KEY   - API key (alternative to username/password)
  VERIFY_CERTS            - Verify SSL certificates (default: true)

Exit Codes:
  0 - Success (indices listed)
  1 - Error (connection failure, authentication error)
  2 - No indices found matching the pattern
EOF
    exit "${1:-1}"
}

# Parse options
case "${1:-}" in
    -h|--help)
        usage 0
        ;;
esac

PATTERN="${1:-}"

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

echo "=== Elasticsearch Indices ==="
echo ""

# Fetch indices
if [ -n "$AUTH_HEADER" ]; then
    INDICES=$(curl $CURL_OPTS -H "$AUTH_HEADER" "$ES_HOST/_cat/indices?format=json&h=index,docs.count,store.size,health,status" 2>/dev/null)
else
    INDICES=$(curl $CURL_OPTS "$ES_HOST/_cat/indices?format=json&h=index,docs.count,store.size,health,status" 2>/dev/null)
fi

# Check response is valid JSON
if ! echo "$INDICES" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
    echo "Error: Could not fetch indices from Elasticsearch." >&2
    echo "Response: $INDICES" >&2
    exit 1
fi

# Process and display
echo "$INDICES" | python3 -c "
import sys
import json
import re

pattern = '$PATTERN'

try:
    indices = json.load(sys.stdin)
except Exception:
    print('Error: Could not parse indices response', file=sys.stderr)
    sys.exit(1)

# Filter out system indices and apply pattern
user_indices = []
for idx in indices:
    name = idx.get('index', '')
    if name.startswith('.'):
        continue
    if pattern and not re.search(pattern, name, re.IGNORECASE):
        continue
    user_indices.append(idx)

# Sort by document count (descending)
user_indices.sort(key=lambda x: -int(x.get('docs.count', 0) or 0))

if not user_indices:
    msg = 'No indices found'
    if pattern:
        msg += f' matching \"{pattern}\"'
    print(msg, file=sys.stderr)
    sys.exit(2)

# Print header
print(f\"{'Index Name':<50} {'Docs':>15} {'Size':>10} {'Health':>8} {'Status':>8}\")
print('-' * 95)

# Print indices
total_docs = 0
for idx in user_indices:
    name = idx.get('index', 'N/A')[:50]
    docs = int(idx.get('docs.count', 0) or 0)
    total_docs += docs
    size = idx.get('store.size', 'N/A')
    health = idx.get('health', 'N/A')
    status = idx.get('status', 'N/A')

    # Health indicator
    health_icon = {'green': '+', 'yellow': '!', 'red': 'X'}.get(health, '?')

    print(f'{name:<50} {docs:>15,} {size:>10} [{health_icon}]{health:>5} {status:>8}')

print('-' * 95)
print(f'Total: {len(user_indices)} indices, {total_docs:,} documents')
"

echo ""
echo "=== Index Patterns ==="
echo ""

# Show common patterns
echo "$INDICES" | python3 -c "
import sys
import json
import re
from collections import defaultdict

try:
    indices = json.load(sys.stdin)
except Exception:
    sys.exit(1)

# Group by pattern (remove date suffixes)
patterns = defaultdict(lambda: {'count': 0, 'docs': 0})

for idx in indices:
    name = idx.get('index', '')
    if name.startswith('.'):
        continue

    # Extract pattern (remove date-like suffixes)
    pattern = re.sub(r'-\d{4}\.\d{2}\.\d{2}.*$', '-*', name)
    pattern = re.sub(r'-\d{6}$', '-*', pattern)
    pattern = re.sub(r'-\d{8}$', '-*', pattern)

    patterns[pattern]['count'] += 1
    patterns[pattern]['docs'] += int(idx.get('docs.count', 0) or 0)

# Sort by doc count
sorted_patterns = sorted(patterns.items(), key=lambda x: -x[1]['docs'])

print(f\"{'Pattern':<50} {'Indices':>10} {'Total Docs':>15}\")
print('-' * 78)

for pattern, stats in sorted_patterns[:20]:
    print(f'{pattern:<50} {stats[\"count\"]:>10} {stats[\"docs\"]:>15,}')
"

echo ""
echo "=== Quick Commands ==="
echo ""
echo "# Search specific index:"
echo "  curl -k -u \$ES_USER:\$ES_PASS \"\$ES_HOST/winlogbeat-*/_search?size=1&pretty\""
echo ""
echo "# Get index mapping:"
echo "  curl -k -u \$ES_USER:\$ES_PASS \"\$ES_HOST/winlogbeat-*/_mapping?pretty\""
echo ""
echo "# Count documents:"
echo "  curl -k -u \$ES_USER:\$ES_PASS \"\$ES_HOST/winlogbeat-*/_count\""
