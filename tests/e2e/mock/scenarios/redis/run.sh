#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../../lib/common.sh
source "$HERE/../../lib/common.sh"

SCENARIO=redis

# The replica mock returns "f" (not banned) for 1.2.3.4, "t" (banned, no end) for 1.2.3.5, and
# a four-line ban whose end is 600s after each read for 1.2.3.7.
# The primary mock always misses. Reads go only to the replica (lapiRedisReadHosts).
body() {
  echo "[$SCENARIO] cached banned IP must be blocked"
  wait_for_status "http://127.0.0.1:${WEB_PORT}/foo" 403 45 -H "X-Forwarded-For: 1.2.3.5"

  echo "[$SCENARIO] the 429 router reads the end line of a cached ban as Retry-After"
  wait_for_status "http://127.0.0.1:${WEB_PORT}/retry" 429 45 -H "X-Forwarded-For: 1.2.3.7"
  assert_header_int_between "http://127.0.0.1:${WEB_PORT}/retry" Retry-After 1 600 -H "X-Forwarded-For: 1.2.3.7"

  echo "[$SCENARIO] a cached ban without an end line gets 429 and no Retry-After"
  assert_status "http://127.0.0.1:${WEB_PORT}/retry" 429 -H "X-Forwarded-For: 1.2.3.5"
  assert_header_absent "http://127.0.0.1:${WEB_PORT}/retry" Retry-After -H "X-Forwarded-For: 1.2.3.5"

  echo "[$SCENARIO] the 403 router sends no Retry-After for the ban with an end"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 403 -H "X-Forwarded-For: 1.2.3.7"
  assert_header_absent "http://127.0.0.1:${WEB_PORT}/foo" Retry-After -H "X-Forwarded-For: 1.2.3.7"

  echo "[$SCENARIO] cached clean IP must pass"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] unknown IP (redis miss) must fall through to LAPI and pass"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.6"
}

run_scenario "$SCENARIO" "$HERE" body
