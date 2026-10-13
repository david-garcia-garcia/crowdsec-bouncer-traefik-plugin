# Requirement
IssueKey: 2026-10-13-count-challenge-once

## Problem
On master, `pkg/bouncer/bouncer.go` `handleAppsecResponseServeHTTP` calls `recordDropped` for every relayed AppSec envelope. A visitor who solves a CrowdSec 1.8 bot-detection challenge therefore increments dropped for the challenge page, `fpscanner.js`, `pow-worker.js`, and `/crowdsec-internal/challenge/submit` (including a successful submit). The live bot-detection spec currently says `blockedRequests` SHALL increment on every relay.

## Current (code)
- `pkg/bouncer/bouncer.go` `handleAppsecResponseServeHTTP` always calls `recordDropped(req, "appsec", "")` before writing the envelope. `recordDropped` increments both the request series (`IncDropped`) and the byte series (`IncDroppedBytes` via `req.EstimatedSize()`).
- `openspec/specs/core_plugin_appsec_bot-detection/spec.md` Requirement "Challenge is relayed to the client" includes `blockedRequests` SHALL increment with no path exception.
- Challenge-page tests (`pkg/bouncer/zzz_bouncer_test.go` `TestHandleNextServeHTTPRelaysStructuredAppsecChallenge`) hit `/protected` and do not assert dropped. No Go production identifier currently names `/crowdsec-internal/challenge/`.
- Ban and plugin-captcha remediations already call `recordDropped` from `handleBanServeHTTP` and `handleCaptchaKindServeHTTP` (`pkg/bouncer/bouncer.go`). AppSec structured `ban` uses `handleBanServeHTTP`, not the relay.
- Dropped counts are read in tests via `pkg/lapi/test_client.go` `TestDroppedCount`. Bytes use `TestDroppedByteCount`.
- Metrics POST shape lives in `pkg/lapi/client_metrics.go` (`IncDropped` / `IncDroppedBytes`). Empty origin/ipType/remediation labels are omitted on POST today.

## Desired
- A relay whose request path is under `/crowdsec-internal/challenge/` MUST NOT increment dropped (request or bytes).
- The challenge page (any other path) still increments dropped once.
- Bans, `pkg/captcha`, and non-challenge AppSec relays stay counted as today.
- Update the bot-detection spec so `blockedRequests` does not increment for a relay under `/crowdsec-internal/challenge/`.
- Do not add origin or remediation labels. Do not change the metrics POST shape.
- Regression: a challenge envelope on `/protected` increments dropped by 1; the same envelope on `/crowdsec-internal/challenge/submit` does not. Use `TestDroppedCount`. Run tests on this machine.
- Delivery card MUST mention upstream https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 point 5. Do not copy that patch.

## Affected
- `pkg/bouncer/bouncer.go` `handleAppsecResponseServeHTTP` / `recordDropped`
- `openspec/specs/core_plugin_appsec_bot-detection/spec.md`
- `pkg/bouncer` tests (new dropped-count cases; existing `TestDroppedCount`)

## Out of scope
- Challenge-path 404 handling
- LAPI decision types
- `.github/workflows`
- Reopening or copying closed PR 195
- A new AppSec JSON parser (master already relays in `handleAppsecResponseServeHTTP`)
- Hardcoded maxlerebourg checkout path or vendor GOPATH copy step
- Origin or remediation labels; metrics POST shape
- Counting changes for bans, `pkg/captcha`, and non-challenge relays

## Unknowns
- Exact prefix match: ticket text is "under `/crowdsec-internal/challenge/`" (trailing slash). Whether `/crowdsec-internal/challenge` with no further segment is counted as the page (increment) or as a callback (skip) is not measured.
- Which path field to read (`URL.Path` vs `RequestURI`) on Traefik origin-form requests.
- Whether an AppSec `captcha` envelope on a callback path also skips dropped (ticket: "non-challenge relays stay counted as today" vs path-based skip on the shared relay).
- Upstream PR 403 point 5 mechanism (must not copy the patch; inspect later).

## Tensions
- Spec vs ticket: `core_plugin_appsec_bot-detection` currently requires `blockedRequests` SHALL increment on every challenge relay; this ticket asks to carve out `/crowdsec-internal/challenge/` so a solve is one drop, not four.
- Closed PR 195 targeted `main` and reimplemented challenge JSON parsing that master already has; this run MUST NOT reopen it and MUST target `master`.
