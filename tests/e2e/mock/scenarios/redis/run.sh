#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../../lib/common.sh
source "$HERE/../../lib/common.sh"

SCENARIO=redis

# The replica mock returns "f" (not banned) for 1.2.3.4 and "t" (banned) for 1.2.3.5.
# The primary mock always misses. Reads go only to the replica (lapiRedisReadHosts).
body() {
  echo "[$SCENARIO] cached banned IP must be blocked"
  wait_for_status "http://127.0.0.1:${WEB_PORT}/foo" 403 45 -H "X-Forwarded-For: 1.2.3.5"

  echo "[$SCENARIO] cached clean IP must pass"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] unknown IP (redis miss) must fall through to LAPI and pass"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.6"
}

run_scenario "$SCENARIO" "$HERE" body
