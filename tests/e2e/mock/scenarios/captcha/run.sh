#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../../lib/common.sh
source "$HERE/../../lib/common.sh"

SCENARIO=captcha

# Solve POST: dummy form field → mocklapi /siteverify → 302 + gate cookie.
# Status stays 200 for captcha page vs backend, so later GETs gate on the body.
body() {
  local url="http://127.0.0.1:${WEB_PORT}/foo"
  local jar="$WORKDIR/captcha.jar"
  local solve_headers="$WORKDIR/solve.headers"

  echo "[$SCENARIO] adding captcha decision for 1.2.3.4"
  lapi_add_decision 1.2.3.4 captcha 5m

  echo "[$SCENARIO] captcha page must be served once the decision is polled (200 + marker)"
  wait_for_body_contains "$url" "E2E_CAPTCHA_PAGE_MARKER" 60 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] captcha response Content-Type is HTML"
  assert_header "$url" Content-Type "text/html; charset=utf-8" -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] captcha response is HTTP 200 (the captcha page itself, not a 403)"
  assert_status "$url" 200 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] non-flagged IP must still pass through to the backend"
  assert_status "$url" 200 -H "X-Forwarded-For: 5.6.7.8"

  echo "[$SCENARIO] POST without dummy field still serves the captcha page"
  assert_status "$url" 200 -X POST -H "X-Forwarded-For: 1.2.3.4"
  assert_body_contains "$url" "E2E_CAPTCHA_PAGE_MARKER" -X POST -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] POST dummy-captcha-response issues 302 and crowdsec_captcha_gate"
  local solve_status solve_body="$WORKDIR/solve.body"
  # Token in query and body: Yaegi FormValue often misses the POST body.
  solve_status=$(curl -sS -D "$solve_headers" -o "$solve_body" -w '%{http_code}' \
    -c "$jar" -X POST --data-urlencode "dummy-captcha-response=ok" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "X-Forwarded-For: 1.2.3.4" \
    "${url}?dummy-captcha-response=ok")
  if [[ "$solve_status" != "302" ]]; then
    echo "[$SCENARIO] solve expected 302, got $solve_status" >&2
    cat "$solve_headers" >&2 || true
    cat "$solve_body" >&2 || true
    return 1
  fi
  if ! tr -d '\r' <"$solve_headers" | grep -qi 'set-cookie:.*crowdsec_captcha_gate='; then
    echo "[$SCENARIO] solve missing Set-Cookie crowdsec_captcha_gate" >&2
    cat "$solve_headers" >&2 || true
    return 1
  fi

  echo "[$SCENARIO] GET with gate cookie and same IP reaches the backend"
  assert_body_contains "$url" "E2E_BACKEND_OK" -b "$jar" -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] GET without cookie still serves the captcha page"
  assert_body_contains "$url" "E2E_CAPTCHA_PAGE_MARKER" -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] GET with gate cookie and another IP is still challenged (bind-IP)"
  assert_body_contains "$url" "E2E_CAPTCHA_PAGE_MARKER" -b "$jar" -H "X-Forwarded-For: 5.6.7.8"
}

run_scenario "$SCENARIO" "$HERE" body
