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

Folded from PR 196 explore:

- Seam: `serveAppSec`, after AppSec did not write and there is no captcha-rule fallthrough, when `subscribeAppSec && !SkipAppsec` and `URL.Path` has prefix `/crowdsec-internal/challenge/`: write 404 and return true. `ServeHTTP` then does not call `next`.
- Keep `applyAppsecServeHTTP` as the writer of relay/ban/captcha-failure. Do not 404 there, so a matched captcha action rule still serves the plugin gate.
- Paths outside the prefix stay allow → `next`. Trusted IPs stay the existing skip in `ServeHTTP`.
- Live contract: `openspec/specs/core_plugin_appsec_bot-detection/spec.md` (MODIFIED: allow/empty 200 must not call `next` on the prefix). Also fold a carve-out into `openspec/specs/core_plugin_appsec_failure-action/spec.md` (passthrough continues to `next` except this prefix when AppSec was in use). README bot-detection sentence.
- Rejected: copy maxlerebourg PR 403 patch (different tree: root `bouncer.go`; ticket forbids copy).
- Rejected: 404 inside `applyAppsecServeHTTP` (would block captcha-rule fallthrough).
- Rejected: new trusted-IP exception (ticket: reuse the existing skip).
- Shared helper: both parts use one prefix constant `crowdsecChallengeCallbackPrefix` and `isCrowdsecChallengeCallbackPath` in `pkg/bouncer/bouncer.go`.

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
  Update (implement, after merging master #206): an AppSec `captcha` no longer reaches the relay; it goes to the captcha gate (`handleCaptchaKindServeHTTP`), which keeps its own `recordDropped`. Only `challenge` and bodied unknown actions reach the relay, so the path skip applies to those alone.

- Q: (folded from PR 196) Does the prefix include exact `/crowdsec-internal/challenge` with no trailing slash?
  Rank: additive asked — new membership test this change adds; Desired names `/crowdsec-internal/challenge/`
  Decision: assumed — `strings.HasPrefix(path, "/crowdsec-internal/challenge/")` as written. The regression path is `custom.js` under that slash.
  By: explore

- Q: (folded from PR 196) Where does 404 run so a captcha action rule still writes the plugin gate?
  Rank: bounded asked — existing `applyAppsecServeHTTP` has 2 production callers in `pkg/bouncer`; Desired says captcha envelope still written as today
  Decision: resolved — 404 in `serveAppSec` after the captcha-rule branch, not inside `applyAppsecServeHTTP`.
  By: explore

- Q: (folded from PR 196) Does SkipAppsec on a challenge path 404 or call `next`?
  Rank: additive asked — Desired says "when AppSec is in use for this request"
  Decision: assumed — SkipAppsec is not AppSec in use; still `next`. No extra skip-rule exception.
  By: explore

- Q: (folded from PR 196) Which 404 helper?
  Rank: additive asked — Desired says respond 404
  Decision: assumed — `http.NotFound(rw, req.Request)` (stdlib 404 + Not Found body).
  By: explore

- Q: (folded from PR 196) Who owns client trust for this path?
  Rank: additive asked — identity already chosen before AppSec
  Decision: resolved — reuse `trustedClients.Checker` skip in `ServeHTTP`; do not re-derive trust here.
  By: explore
