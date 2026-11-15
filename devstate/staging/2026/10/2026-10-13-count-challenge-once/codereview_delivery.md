# Delivery

## Motivation
A visitor who solves a CrowdSec 1.8 bot-detection challenge sends several requests that the plugin relays from AppSec: the challenge page, `/crowdsec-internal/challenge/fpscanner.js`, `/crowdsec-internal/challenge/pow-worker.js`, and a POST to `/crowdsec-internal/challenge/submit`. Before this change each relayed envelope was counted as a drop in the usage metrics, so one solve was reported as several blocked requests (an explore run with a throwaway test saw the count go from 1 to 2). The live bot-detection spec also required `blockedRequests` to increment on every relay, with no exception.

The effect is inflated `blockedRequests` and dropped-bytes figures for any deployment using bot-detection challenges. Upstream https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 point 5 describes the same need: count the challenge page once and skip the internal scripts and submit. This change does not copy that patch.

Priority: P3 — usage-metric counting is inflated and the spec is wrong, with no data loss or unsafe behaviour

## Implementation
`handleAppsecResponseServeHTTP` in `pkg/bouncer/bouncer.go` now skips `recordDropped` when the request path starts with the new constant `/crowdsec-internal/challenge/` (helper `isCrowdsecChallengeCallbackPath`). Any other path, including the challenge page itself, is still counted once with origin `appsec`. Bans, plugin captcha and other AppSec relays are untouched, and no labels or metrics POST shape changed. A regression test relays the same challenge envelope on `/protected` (expects 1 request and bytes > 0) and on `/crowdsec-internal/challenge/submit` (expects 0 requests and 0 bytes), read through `TestDroppedCount` and `TestDroppedByteCount`.

Master was merged in at a192cb60 (it brought #191, #194, #198, #201, #206, #207, #208, #209). The only conflict was in `pkg/bouncer/bouncer.go`, where both sides added a const and master renamed the literal "appsec" to `originAppsec`; the resolution keeps both and the skip path uses `originAppsec`. The OpenSpec delta (`count-challenge-drop-once`) was rebuilt on master's post-#206 requirement text, so archiving it does not revert #206. Locally, `go test ./...` and `golangci-lint` passed after the merge.

## What this changes
**Operators.** Usage-metric `blockedRequests` and dropped bytes for AppSec bot-detection no longer include the `/crowdsec-internal/challenge/` scripts and submit, so a solve counts once; no config change.
**Admin users.** None.
**Developers.** The bot-detection spec now exempts relays under `/crowdsec-internal/challenge/` from the `blockedRequests` increment; the exemption applies to any AppSec envelope on that path prefix.
**End users.** None.
