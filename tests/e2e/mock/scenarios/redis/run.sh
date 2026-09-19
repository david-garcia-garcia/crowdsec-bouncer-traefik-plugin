#!/usr/bin/env bash
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=../../lib/common.sh
source "$HERE/../../lib/common.sh"

SCENARIO=redis

# The replica mock returns "f" (not banned) for 1.2.3.4 and "t" (banned) for 1.2.3.5.
# The primary mock always misses. redisCacheReadHosts is [replica, primary] and the round-robin
# lands on the primary first, so every other rotated read is served by the replica.
#
# Rotation is only observable on a key this bouncer has not just written: a key it wrote reads from
# the writer for the pin window, so that a decision it has just stored is never read back from a
# read host that has not received it. Live mode memoises every lookup, so each probe below uses a
# key whose previous request did not write it.
body() {
  echo "[$SCENARIO] unknown IP takes the primary slot, which misses, so the next rotated read is the replica"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.9"

  echo "[$SCENARIO] cached banned IP must be blocked, served from the replica"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 403 -H "X-Forwarded-For: 1.2.3.5"

  echo "[$SCENARIO] serving a ban writes nothing, so the same IP rotates to the primary and misses"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.5"

  echo "[$SCENARIO] cached clean IP must pass"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.4"

  echo "[$SCENARIO] unknown IP (redis miss) must fall through to LAPI and pass"
  assert_status "http://127.0.0.1:${WEB_PORT}/foo" 200 -H "X-Forwarded-For: 1.2.3.6"
}

run_scenario "$SCENARIO" "$HERE" body
