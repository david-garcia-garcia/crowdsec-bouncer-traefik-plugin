#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../../lib/common.sh
source "$HERE/../../lib/common.sh"

SCENARIO=request-bypass-rules

body() {
  echo "[$SCENARIO] adding ban decision for 1.2.3.4"
  lapi_add_decision 1.2.3.4 ban 5m

  echo "[$SCENARIO] banned IP on a non-matching path must be blocked (HTTP 403)"
  wait_for_status "http://127.0.0.1:${WEB_PORT}/foo" 403 45 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] banned IP on a LAPI-matching path must reach origin (HTTP 200)"
  assert_status "http://127.0.0.1:${WEB_PORT}/healthz" 200 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] banned IP on a host-matching request must reach origin (HTTP 200)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.4" -H "Host: probe.example"

  echo "[$SCENARIO] AppSec 403 URI must be blocked when no AppSec rule matches (HTTP 403)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo/403" 403 -H "X-Forwarded-For: 5.6.7.8"

  echo "[$SCENARIO] AppSec 403 URI must be skipped on an AppSec-matching path (HTTP 200)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo/403-skip" 200 -H "X-Forwarded-For: 5.6.7.8"

  echo "[$SCENARIO] LAPI match must not skip AppSec (HTTP 403)"
  assert_status "http://127.0.0.1:${WEB_PORT}/lapi-skip/403" 403 -H "X-Forwarded-For: 5.6.7.8"

  echo "[$SCENARIO] AppSec match must not skip LAPI (HTTP 403)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo/403-skip" 403 -H "X-Forwarded-For: 1.2.3.4"
}

run_scenario "$SCENARIO" "$HERE" body
