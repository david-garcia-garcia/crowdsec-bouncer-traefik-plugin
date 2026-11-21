#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../../lib/common.sh
source "$HERE/../../lib/common.sh"

SCENARIO=live-mode

body() {
  echo "[$SCENARIO] no decision -> first hit queries LAPI, returns 200, caches 'allowed' for 2s"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] adding ban decision for 1.2.3.4"
  lapi_add_decision 1.2.3.4 ban 5m

  # Stays 200 until the cached 'allowed' (lapiDefaultDecisionSeconds) expires, then
  # the re-query sees the ban — poll instead of guessing the cache TTL.
  echo "[$SCENARIO] hit must turn 403 once the cached 'allowed' expires and LAPI is re-queried"
  wait_for_status "http://127.0.0.1:${WEB_PORT}/foo" 403 45 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] the 403 router sends no Retry-After"
  assert_header_absent "http://127.0.0.1:${WEB_PORT}/foo" Retry-After -H "X-Forwarded-For: 1.2.3.4"

  # The cache entry lives lapiDefaultDecisionSeconds (2s); Retry-After reports the 5m decision, not that entry.
  echo "[$SCENARIO] the 429 router answers the same ban with Retry-After past the 2s cache TTL, at most 300"
  wait_for_status "http://127.0.0.1:${WEB_PORT}/retry" 429 45 -H "X-Forwarded-For: 1.2.3.4"
  assert_header_int_between "http://127.0.0.1:${WEB_PORT}/retry" Retry-After 3 300 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] another non-banned IP must still pass"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 5.6.7.8"
}

run_scenario "$SCENARIO" "$HERE" body
