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

## Folded in: PR 197 also carries PR 196
Requested by the owner in chat on 2026-11-15: fold https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/196 (`2026-10-13-terminate-challenge-paths`) into this PR; both act on the `/crowdsec-internal/challenge/` prefix. That run's own requirement stays at `devstate/2026/10/2026-10-13-terminate-challenge-paths/requirement.md`. Its Desired, verbatim:

When AppSec is in use for this request and the URL path is under `/crowdsec-internal/challenge/`, and AppSec did not itself produce a response the bouncer is relaying or a ban the bouncer is writing, respond 404 and do not call `next`. A real challenge, captcha, or ban envelope for that path is still written as today. Paths outside the prefix are unchanged. Do not add a new trusted-IP exception; trusted IPs that already skip the bouncer before this code stay as they are.

Update the live spec and the README sentence that says the prefix is safe whenever the middleware covers the host.

Regression test: AppSec HTTP 200 on `/crowdsec-internal/challenge/custom.js` is 404 and `next` is not called. A normal path that AppSec allows still calls `next`. Run the tests on this machine.

Upstream source for that part: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 point 4. Do not copy that patch.
