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
  local solve_status solve_body="$WORKDIR/solve.body" cookie=""
  # Token in query and body: Yaegi FormValue often misses the POST body.
  solve_status=$(curl -sS -D "$solve_headers" -o "$solve_body" -w '%{http_code}' \
    -X POST --data-urlencode "dummy-captcha-response=ok" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "X-Forwarded-For: 1.2.3.4" \
    "${url}?dummy-captcha-response=ok")
  cookie=$(tr -d '\r' <"$solve_headers" \
    | awk 'BEGIN{IGNORECASE=1} /^set-cookie:[[:space:]]*crowdsec_captcha_gate=/ { sub(/^set-cookie:[[:space:]]*/,""); print; exit }' \
    | cut -d';' -f1)
  if [[ "$solve_status" != "302" || -z "$cookie" ]]; then
    {
      echo "[$SCENARIO] solve expected 302 + crowdsec_captcha_gate, got $solve_status cookie='$cookie'"
      cat "$solve_headers" || true
      cat "$solve_body" || true
    } | tee "$WORKDIR/failure.txt" >&2
    return 1
  fi

  echo "[$SCENARIO] GET with gate cookie and same IP reaches the backend"
  assert_body_contains "$url" "E2E_BACKEND_OK" -H "Cookie: $cookie" -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] GET without cookie still serves the captcha page"
  assert_body_contains "$url" "E2E_CAPTCHA_PAGE_MARKER" -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] GET with gate cookie and another IP is still challenged (bind-IP)"
  assert_body_contains "$url" "E2E_CAPTCHA_PAGE_MARKER" -H "Cookie: $cookie" -H "X-Forwarded-For: 5.6.7.8"
}

run_scenario "$SCENARIO" "$HERE" body
