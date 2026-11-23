#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../../lib/common.sh
source "$HERE/../../lib/common.sh"

SCENARIO=appsec

# Assert the last Traefik access-log line that contains PATTERN (fixed string) answered within
# MIN_MS..MAX_MS. Usage: assert_access_log_answered_within PATTERN MIN_MS MAX_MS
assert_access_log_answered_within() {
  local pattern="$1" min_ms="$2" max_ms="$3" line elapsed_ms
  line=$(grep -F "$pattern" "$WORKDIR/traefik.log" | tail -n 1 || true)
  elapsed_ms=$(sed -n 's/.* \([0-9][0-9]*\)ms$/\1/p' <<<"$line")
  echo "[$SCENARIO]   access log: ${line:-<none>}"
  if [[ -z "$elapsed_ms" || "$elapsed_ms" -lt "$min_ms" || "$elapsed_ms" -gt "$max_ms" ]]; then
    echo "assert_access_log_answered_within: no \"$pattern\" line in ${min_ms}..${max_ms}ms (got: ${line:-<none>})" | tee "$WORKDIR/failure.txt" >&2
    return 1
  fi
}

# Assert a header dump curl wrote with -D contains LINE (fixed string, any case, CR stripped).
# Usage: assert_saved_header FILE LINE
assert_saved_header() {
  local file="$1" want="$2"
  if ! tr -d '\r' < "$file" 2>/dev/null | grep -qiF "$want"; then
    echo "assert_saved_header: \"$want\" not in $(basename "$file"): $(tr -d '\r' < "$file" 2>/dev/null | tr '\n' ' ')" | tee "$WORKDIR/failure.txt" >&2
    return 1
  fi
}

# AppSec wiring check: the plugin forwards each request to the AppSec engine and
# enforces its verdict. The mock emulates one virtual-patching rule (block any
# URI containing "rpc2"), mirroring examples/appsec-enabled. This proves the
# plugin's AppSec path end to end (header forwarding + allow/block handling); it
# does not test the real WAF's detection accuracy.
body() {
  echo "[$SCENARIO] benign request must pass (AppSec 200)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] request that return 403 must be blocked (AppSec 403)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo/403" 403 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] AppSec ban with http_status 418 (SetReturnCode) is answered with 418"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo/appsec-418" 418 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] structured challenge JSON is relayed (status/body/cookie)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo/challenge" 200 -H "X-Forwarded-For: 1.2.3.4"
  assert_body_contains "http://127.0.0.1:${WEB_PORT}/foo/challenge" "e2e-challenge" -H "X-Forwarded-For: 1.2.3.4"
  assert_header "http://127.0.0.1:${WEB_PORT}/foo/challenge" "Set-Cookie" "__crowdsec_challenge=e2e; Path=/; HttpOnly" -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] AppSec captcha on a router without captcha is a downgrade ban (403)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo/appsec-captcha" 403 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] request that return 500 must be blocked (bouncerAppsecFailureAction=ban) (AppSec 500)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo/500" 403 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] request that return 502 must be blocked (bouncerAppsecFailureAction=ban) (Proxy error 502)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo/502" 403 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] request that send bad body after appsecBodyLimit must pass (AppSec 200)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.4" -X POST -d "______&a=0"

  echo "[$SCENARIO] request that send bad body before appsecBodyLimit must pass (AppSec 403)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 403 -H "X-Forwarded-For: 1.2.3.4" -X POST -d "a=0&______"

  echo "[$SCENARIO] request http2 that send no body GET (AppSec 200)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.4" --http2-prior-knowledge -H "Content-Length:"

  # A body without Content-Length is read and inspected like any other (appsecBodyLimit: 4).
  # Both lines are POSTs: curl -d implies POST.
  echo "[$SCENARIO] request http2 POST (curl -d) without Content-Length is inspected and allowed (AppSec 200)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.4" --http2-prior-knowledge -H "Content-Length:" -d "test"

  echo "[$SCENARIO] request http2 POST without Content-Length is inspected and allowed (AppSec 200)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.4" --http2-prior-knowledge -H "Content-Length:" -X POST -d "test"

  echo "[$SCENARIO] request http2 POST without Content-Length and a bad body is blocked (AppSec 403)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 403 -H "X-Forwarded-For: 1.2.3.4" --http2-prior-knowledge -H "Content-Length:" -X POST -d "a=0&"

  echo "[$SCENARIO] request http2 DELETE without Content-Length and a bad body is blocked (AppSec 403)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 403 -H "X-Forwarded-For: 1.2.3.4" --http2-prior-knowledge -H "Content-Length:" -X DELETE -d "a=0&"

  echo "[$SCENARIO] request http2 empty POST without Content-Length (restic init shape) is allowed (AppSec 200)"
  printf '' | assert_status "http://127.0.0.1:${WEB_PORT}/foo/?create=true" 200 -H "X-Forwarded-For: 1.2.3.4" --http2-prior-knowledge -H "Content-Length:" -H "Expect:" -X POST -T -

  echo "[$SCENARIO] request http1.1 chunked POST with a bad body is blocked (AppSec 403)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 403 -H "X-Forwarded-For: 1.2.3.4" --http1.1 -H "Transfer-Encoding: chunked" -X POST -d "a=0&"

  # Body read deadline (/stream: appsecBodyReadTimeoutSeconds 2, failure action passthrough).
  # curl sends a body without Content-Length from stdin. It only sends the request once stdin yields
  # its first byte, so each body starts at once and then pauses; a 5 s pause is past the deadline.
  # Traefik's access log shows when it answered: at the 2 s deadline on both protocols (Traefik
  # v3.7.19, measured), not when the body ends at 5 s.
  echo "[$SCENARIO] request http1.1 chunked body that ends in time is inspected and allowed (AppSec 200)"
  (printf 'x'; sleep 1; printf 'y') | assert_status "http://127.0.0.1:${WEB_PORT}/stream/h1-in-time" 200 -H "X-Forwarded-For: 1.2.3.4" --http1.1 -H "Expect:" -X POST -T - --max-time 10

  echo "[$SCENARIO] request http2 body without Content-Length that ends in time is inspected and allowed (AppSec 200)"
  (printf 'x'; sleep 1; printf 'y') | assert_status "http://127.0.0.1:${WEB_PORT}/stream/h2-in-time" 200 -H "X-Forwarded-For: 1.2.3.4" --http2-prior-knowledge -H "Content-Length:" -H "Expect:" -X POST -T - --max-time 10

  echo "[$SCENARIO] request http1.1 chunked body that stalls past the deadline is blocked 400 with passthrough"
  ( (printf 'x'; sleep 5; printf 'y') | curl -s -o /dev/null -D "$WORKDIR/h1-stall.headers" -H "X-Forwarded-For: 1.2.3.4" --http1.1 -H "Expect:" -X POST -T - --max-time 10 "http://127.0.0.1:${WEB_PORT}/stream/h1-stall" ) || true
  assert_saved_header "$WORKDIR/h1-stall.headers" "x-remediation: error:body-read-timeout"
  assert_access_log_answered_within '"POST /stream/h1-stall HTTP/1.1" 400 ' 1500 3500

  echo "[$SCENARIO] request http2 body without Content-Length that stalls past the deadline is blocked 400 with passthrough"
  ( (printf 'x'; sleep 5; printf 'y') | curl -s -o /dev/null -D "$WORKDIR/h2-stall.headers" -H "X-Forwarded-For: 1.2.3.4" --http2-prior-knowledge -H "Content-Length:" -H "Expect:" -X POST -T - --max-time 10 "http://127.0.0.1:${WEB_PORT}/stream/h2-stall" ) || true
  assert_saved_header "$WORKDIR/h2-stall.headers" "x-remediation: error:body-read-timeout"
  assert_access_log_answered_within '"POST /stream/h2-stall HTTP/2.0" 400 ' 1500 3500
}

run_scenario "$SCENARIO" "$HERE" body
