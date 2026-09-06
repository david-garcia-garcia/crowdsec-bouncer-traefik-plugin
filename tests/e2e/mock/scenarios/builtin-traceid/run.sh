#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../../lib/common.sh
source "$HERE/../../lib/common.sh"

SCENARIO=builtin-traceid

body() {
  echo "[$SCENARIO] adding ban decision"
  lapi_add_decision 1.2.3.4 ban 5m

  echo "[$SCENARIO] banned response becomes 403 once the next stream poll lands"
  wait_for_status "http://127.0.0.1:${WEB_PORT}/foo" 403 45 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] built-in X-Trace-ID is 16 lowercase hex and matches the ban body"
  local headers body trace
  headers=$(mktemp)
  body=$(mktemp)
  curl -s -D "$headers" -o "$body" -H "X-Forwarded-For: 1.2.3.4" "http://127.0.0.1:${WEB_PORT}/foo"
  trace=$(tr -d '\r' <"$headers" | awk -F': ' 'tolower($1) == "x-trace-id" { print $2; exit }')
  if [[ ! "$trace" =~ ^[0-9a-f]{16}$ ]]; then
    echo "[$SCENARIO] expected 16 lowercase hex X-Trace-ID, got \"$trace\"" >&2
    cat "$headers" >&2
    return 1
  fi
  if ! grep -q "trace: ${trace}" "$body"; then
    echo "[$SCENARIO] body missing generated trace id ${trace}:" >&2
    cat "$body" >&2
    return 1
  fi
  rm -f "$headers" "$body"
}

run_scenario "$SCENARIO" "$HERE" body
