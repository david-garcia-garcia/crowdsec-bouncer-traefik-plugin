# Explore

## Concepts

- AppSec relay: `pkg/bouncer/bouncer.go` `handleAppsecResponseServeHTTP`. Writes a structured AppSec envelope to the client. Today it always calls `recordDropped(req, "appsec", "")`.
- Dropped window: `recordDropped` calls `lapi.Client.IncDropped` (unit request) and `IncDroppedBytes` (unit byte via `req.EstimatedSize()`). Tests read the request series with `pkg/lapi/test_client.go` `TestDroppedCount`.
- Ban and plugin captcha: `handleBanServeHTTP` and `handleCaptchaKindServeHTTP` also call `recordDropped`. AppSec JSON action `ban` uses `handleBanServeHTTP`, not the relay. Those paths stay counted.
- Challenge callbacks: CrowdSec 1.8 browser solve loads `/crowdsec-internal/challenge/fpscanner.js`, `/crowdsec-internal/challenge/pow-worker.js`, and POSTs `/crowdsec-internal/challenge/submit`. Official prefix to keep off origin: `/crowdsec-internal/challenge/*` (`knowledge/research/ext_crowdsec_appsec_bot-detection/`).
- Live spec: `openspec/specs/core_plugin_appsec_bot-detection/spec.md` currently says `blockedRequests` SHALL increment on every challenge relay.

Seam: protected GET gets an AppSec challenge, `handleAppsecResponseServeHTTP` records dropped +1. The same envelope on a callback GET/POST records dropped +1 again (bug). Ban and pkg/captcha stay on their own `recordDropped` calls.

Call sites of `recordDropped`: 3, all in `pkg/bouncer/bouncer.go` (`handleBanServeHTTP`, `handleCaptchaKindServeHTTP`, `handleAppsecResponseServeHTTP`). Only the relay is the skip.

Reproduce: throwaway `TestExploreChallengeDroppedOnSubmitPath` (deleted). Bound LAPI metrics on `testBouncerWithAppsec`. Challenge envelope on `/protected` -> `TestDroppedCount("appsec","ipv4","")` = 1. Same envelope on POST `/crowdsec-internal/challenge/submit` -> count became 2. Claimed extra increment is real.

Outside facts: `knowledge/research/ext_crowdsec_appsec_bot-detection/` (callback paths); `knowledge/research/ext_crowdsec_lapi_usage-metrics/` (item name `dropped`, not `blocked`). Upstream https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 point 5 is the ask (count the page once; skip internal scripts/submit). Do not copy that patch. Master already parses and relays in `handleAppsecResponseServeHTTP`.

## Decisions

- Chosen seam: one path guard in `handleAppsecResponseServeHTTP` before `recordDropped`. Prefix `/crowdsec-internal/challenge/` on `req.URL.Path`. Skipping `recordDropped` skips both request and bytes. Do not add origin/remediation labels. Do not change the metrics POST shape.
- Live contract: `core_plugin_appsec_bot-detection` - change `blockedRequests` SHALL increment so a relay under `/crowdsec-internal/challenge/` does not increment dropped (request or bytes); any other path still increments once.
- Rejected: reopen/copy closed PR 195 (wrong base `main`, reimplemented JSON parse). Rejected: copy upstream PR 403. Rejected: a new AppSec JSON parser. Rejected: skip inside `recordDropped` (would affect ban/captcha). Rejected: challenge-path 404 (out of scope).
- Regression: challenge envelope on `/protected` increments `TestDroppedCount` by 1; same envelope on `/crowdsec-internal/challenge/submit` does not.

## Open questions

- Q: Which request path field implements the challenge-callback prefix?
  Rank: additive asked — Desired names the path prefix; httprule already matches URL.Path (1 family in pkg/httprule, enumerated with pkg/bouncer/bouncer.go)
  Decision: assumed — use req.URL.Path with strings.HasPrefix and /crowdsec-internal/challenge/. Traefik ServeHTTP fills URL.Path; do not parse RequestURI.
  By: explore

- Q: Does exact /crowdsec-internal/challenge with no extra segment skip dropped?
  Rank: additive asked — Desired text is under /crowdsec-internal/challenge/ with the trailing slash
  Decision: assumed — that exact path still increments (it is not under the slash prefix). CrowdSec callbacks are /challenge/submit, /challenge/fpscanner.js, /challenge/pow-worker.js.
  By: explore

- Q: Does an AppSec captcha or other non-challenge envelope on a callback path skip dropped?
  Rank: additive asked — Desired: path-based skip on relay; bans, pkg/captcha, and non-challenge relays stay counted as today
  Decision: assumed — skip is only in handleAppsecResponseServeHTTP and is path-based. Ban and pkg/captcha never enter that function so they stay counted. AppSec captcha on a normal path still counts. A captcha envelope on the callback prefix would skip (same shared relay); that case is not in the regression.
  By: explore
