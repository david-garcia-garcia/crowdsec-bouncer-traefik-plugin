#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../../lib/common.sh
source "$HERE/../../lib/common.sh"

SCENARIO=appsec-captcha

# AppSec answers {"action":"captcha","http_status":403} (no page, as CrowdSec does)
# for GET /foo/appsec-captcha and allows the form POST to the same URI. The
# router serves its own captcha, validates the POST AppSec let through, and the
# gate cookie then clears the AppSec captcha.
body() {
  local url="http://127.0.0.1:${WEB_PORT}/foo/appsec-captcha"
  local solve_headers="$WORKDIR/solve.headers"

  echo "[$SCENARIO] benign request passes"
  assert_body_contains "http://127.0.0.1:${WEB_PORT}/foo" "E2E_BACKEND_OK" -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] AppSec captcha serves the router captcha page (200 + marker + captcha:appsec)"
  assert_status "$url" 200 -H "X-Forwarded-For: 1.2.3.4"
  assert_body_contains "$url" "E2E_CAPTCHA_PAGE_MARKER" -H "X-Forwarded-For: 1.2.3.4"
  assert_header "$url" "X-Remediation" "captcha:appsec" -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] captcha form POST allowed by AppSec issues 302 and crowdsec_captcha_gate"
  local solve_status solve_body="$WORKDIR/solve.body" cookie=""
  solve_status=$(curl -sS -D "$solve_headers" -o "$solve_body" -w '%{http_code}' \
    -X POST --data-urlencode "crowdsec_captcha_challenge=v1" --data-urlencode "dummy-captcha-response=ok" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -H "X-Forwarded-For: 1.2.3.4" \
    "$url")
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

  echo "[$SCENARIO] GET with the gate cookie clears the AppSec captcha and reaches the backend"
  assert_body_contains "$url" "E2E_BACKEND_OK" -H "Cookie: $cookie" -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] GET without the cookie is still challenged"
  assert_body_contains "$url" "E2E_CAPTCHA_PAGE_MARKER" -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] ordinary POST allowed by AppSec reaches the backend"
  assert_body_contains "$url" "E2E_BACKEND_OK" -X POST -d "username=alice" -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] unknown AppSec action without a page is a ban (403 + ban:appsec-action-empty)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo/appsec-tarpit" 403 -H "X-Forwarded-For: 1.2.3.4"
  assert_header "http://127.0.0.1:${WEB_PORT}/foo/appsec-tarpit" "X-Remediation" "ban:appsec-action-empty" -H "X-Forwarded-For: 1.2.3.4"
}

run_scenario "$SCENARIO" "$HERE" body
