#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../../lib/common.sh
source "$HERE/../../lib/common.sh"

SCENARIO=appsec

# Assert the last Traefik access-log line matching PATTERN (fixed string) took at most MAX_MS.
# Usage: assert_access_log_answered_within PATTERN MAX_MS
assert_access_log_answered_within() {
  local pattern="$1" max_ms="$2" line elapsed_ms
  line=$(grep -F "$pattern" "$WORKDIR/traefik.log" | tail -n 1 || true)
  elapsed_ms=$(sed -n 's/.* \([0-9][0-9]*\)ms$/\1/p' <<<"$line")
  if [[ -z "$elapsed_ms" || "$elapsed_ms" -gt "$max_ms" ]]; then
    echo "assert_access_log_answered_within: no \"$pattern\" line within ${max_ms}ms (got: ${line:-<none>})" | tee "$WORKDIR/failure.txt" >&2
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

  echo "[$SCENARIO] structured challenge JSON is relayed (status/body/cookie)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo/challenge" 200 -H "X-Forwarded-For: 1.2.3.4"
  assert_body_contains "http://127.0.0.1:${WEB_PORT}/foo/challenge" "e2e-challenge" -H "X-Forwarded-For: 1.2.3.4"
  assert_header "http://127.0.0.1:${WEB_PORT}/foo/challenge" "Set-Cookie" "__crowdsec_challenge=e2e; Path=/; HttpOnly" -H "X-Forwarded-For: 1.2.3.4"

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

  # Bodies without Content-Length are read and inspected like any other (appsecBodyLimit: 4).
  echo "[$SCENARIO] request http2 POST (curl -d) without Content-Length is inspected and allowed (AppSec 200)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.4" --http2-prior-knowledge -H "Content-Length:" -d "test"

  echo "[$SCENARIO] request http2 POST without Content-Length is inspected and allowed (AppSec 200)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.4" --http2-prior-knowledge -H "Content-Length:" -X POST -d "test"

  echo "[$SCENARIO] request http2 POST without Content-Length and bad body is blocked (AppSec 403)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 403 -H "X-Forwarded-For: 1.2.3.4" --http2-prior-knowledge -H "Content-Length:" -X POST -d "a=0&"

  echo "[$SCENARIO] request http2 DELETE without Content-Length and bad body is blocked (AppSec 403)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 403 -H "X-Forwarded-For: 1.2.3.4" --http2-prior-knowledge -H "Content-Length:" -X DELETE -d "a=0&"

  echo "[$SCENARIO] request http1.1 chunked POST with bad body is blocked (AppSec 403)"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 403 -H "X-Forwarded-For: 1.2.3.4" -H "Transfer-Encoding: chunked" -X POST -d "a=0&"

  # Body read timeout (/stream: appsecBodyReadTimeoutSeconds 2, failure action passthrough).
  # curl sends a body without Content-Length from stdin. It cannot read an answer while it waits
  # on stdin, so a body that ends late (4s) is how the block is observed on HTTP/1.1.
  echo "[$SCENARIO] request http1.1 chunked body that ends in time is inspected and allowed (AppSec 200)"
  (sleep 1; printf 'x') | assert_status "http://127.0.0.1:${WEB_PORT}/stream" 200 -H "X-Forwarded-For: 1.2.3.4" --http1.1 -H "Expect:" -X POST -T - --max-time 8

  echo "[$SCENARIO] request http2 body without Content-Length that ends in time is inspected and allowed (AppSec 200)"
  (sleep 1; printf 'x') | assert_status "http://127.0.0.1:${WEB_PORT}/stream" 200 -H "X-Forwarded-For: 1.2.3.4" --http2-prior-knowledge -H "Content-Length:" -H "Expect:" -X POST -T - --max-time 8

  # Through Traefik the HTTP/1.1 read is not cut at the deadline (measured): the request is
  # blocked once the client ends its body (or at Traefik's readTimeout), never let through.
  echo "[$SCENARIO] request http1.1 chunked body that ends after the timeout is blocked whatever the failure action"
  (sleep 4; printf 'x') | assert_status "http://127.0.0.1:${WEB_PORT}/stream" 403 -H "X-Forwarded-For: 1.2.3.4" --http1.1 -H "Expect:" -X POST -T - --max-time 8
  (sleep 4; printf 'x') | assert_header "http://127.0.0.1:${WEB_PORT}/stream" "X-Remediation" "ban:appsec-body-timeout" -H "X-Forwarded-For: 1.2.3.4" --http1.1 -H "Expect:" -X POST -T - --max-time 8

  # HTTP/2 is cut at the deadline. curl only reads the stream after stdin ends, when the server
  # has already answered and reset it, so the answer is checked in Traefik's access log.
  echo "[$SCENARIO] request http2 stream without Content-Length is blocked at the body read timeout"
  ( (sleep 4; printf 'x') | curl -s -o /dev/null -H "X-Forwarded-For: 1.2.3.4" --http2-prior-knowledge -H "Content-Length:" -H "Expect:" -X POST -T - --max-time 8 "http://127.0.0.1:${WEB_PORT}/stream" ) || true
  assert_access_log_answered_within '"POST /stream HTTP/2.0" 403 ' 3000
}

run_scenario "$SCENARIO" "$HERE" body
