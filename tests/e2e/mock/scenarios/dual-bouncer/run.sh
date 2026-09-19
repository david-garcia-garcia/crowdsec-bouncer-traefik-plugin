#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../../lib/common.sh
source "$HERE/../../lib/common.sh"

SCENARIO=dual-bouncer
export LAPI_PORT_B="${LAPI_PORT_B:-8095}"

body() {
  echo "[$SCENARIO] ban 1.2.3.4 only on LAPI A"
  lapi_add_decision_at "${LAPI_PORT}" 1.2.3.4 ban 5m

  echo "[$SCENARIO] router A (LAPI A) must forbid the banned IP"
  wait_for_status "http://127.0.0.1:${WEB_PORT}/a" 403 45 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] router B (LAPI B) must allow the same IP (first-wins would 403)"
  wait_for_status "http://127.0.0.1:${WEB_PORT}/b" 200 45 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] a clean IP still passes both routers"
  assert_status "http://127.0.0.1:${WEB_PORT}/a" 200 -H "X-Forwarded-For: 5.6.7.8"
  assert_status "http://127.0.0.1:${WEB_PORT}/b" 200 -H "X-Forwarded-For: 5.6.7.8"
}

run_scenario "$SCENARIO" "$HERE" body
