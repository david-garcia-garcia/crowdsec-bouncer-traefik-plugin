#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../../lib/common.sh
source "$HERE/../../lib/common.sh"

SCENARIO=captcha-ban-origins

# banToCaptchaOrigins: ["CAPI", "lists:firehol_level1"] — listed bans render captcha;
# other list names and unlisted origins stay 403.
body() {
  local url="http://127.0.0.1:${WEB_PORT}/foo"

  echo "[$SCENARIO] ban from listed origin CAPI must render the captcha page"
  lapi_add_decision 1.2.3.4 ban 5m CAPI
  wait_for_body_contains "$url" "E2E_CAPTCHA_PAGE_MARKER" 15 -H "X-Forwarded-For: 1.2.3.4"
  assert_status "$url" 200 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] ban from lists:firehol_level1 must render the captcha page"
  lapi_add_decision 1.2.3.5 ban 5m lists firehol_level1
  wait_for_body_contains "$url" "E2E_CAPTCHA_PAGE_MARKER" 15 -H "X-Forwarded-For: 1.2.3.5"

  echo "[$SCENARIO] ban from another list (tor-exit) must stay a 403"
  lapi_add_decision 1.2.3.6 ban 5m lists tor-exit
  wait_for_status "$url" 403 15 -H "X-Forwarded-For: 1.2.3.6"

  echo "[$SCENARIO] ban from unlisted origin cscli must stay a 403"
  lapi_add_decision 1.2.3.7 ban 5m cscli
  wait_for_status "$url" 403 15 -H "X-Forwarded-For: 1.2.3.7"

  echo "[$SCENARIO] a captcha decision is unaffected by the mapping"
  lapi_add_decision 1.2.3.8 captcha 5m crowdsec
  wait_for_body_contains "$url" "E2E_CAPTCHA_PAGE_MARKER" 15 -H "X-Forwarded-For: 1.2.3.8"

  echo "[$SCENARIO] an IP with no decision still reaches the backend"
  assert_status "$url" 200 -H "X-Forwarded-For: 5.6.7.8"
}

run_scenario "$SCENARIO" "$HERE" body
