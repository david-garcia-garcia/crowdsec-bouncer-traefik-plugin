# Requirement
IssueKey: 2026-09-26-remediation-header-reasons

# Structured remediation response header for Traefik access logs

## Problem

`bouncerRemediationHeadersCustomName` is an optional **response** header so Traefik JSON access logs (`downstream_<Name>`) can tell a plugin bounce from an origin 403. Upstream issue maxlerebourg/crowdsec-bouncer-traefik-plugin#186 / PR #189. Today the value is only the kind: `ban`, `captcha`, `solved-captcha`, `error:client-disconnected`, or a raw AppSec `action`. Origin/reason (forced decision header, LAPI, AppSec, failure-action, tech) is known internally for usage-metrics but not on the header. Pass/bypass/trusted/passthrough/503 stay **absent** (do not add `allow: pass`).

## Desired

When that header name is configured, write structured values. Grammar: `kind:reason` or `kind:reason:origin`. **`:` is the field separator.** Split at most three fields on `:`. Closed reasons never take a third field.

### Closed vocabulary

| Header | Meaning |
| ------ | ------- |
| `ban:decision-header` | Incoming `bouncerDecisionHeader` is `b` |
| `ban:lapi` | CrowdSec decision type ban, empty metrics origin (intern overflow / packed Range with no origin) |
| `ban:lapi:<origin>` | CrowdSec decision type ban; third field is header-safe metrics origin (see Origin encoding) |
| `ban:lapi-failure` | LAPI down / unpublished, fail-closed ban |
| `ban:stream-unhealthy` | Stream miss + unhealthy, fail-closed ban |
| `ban:cache-fail` | Redis/cache fail-closed |
| `ban:unparseable-request` | `GetRemoteIP` failed or client IP would not parse |
| `ban:appsec` | AppSec JSON `action: ban` |
| `ban:appsec-challenge-empty` | AppSec `action: challenge` with empty body (fail-closed to ban page) |
| `ban:appsec-failure` | AppSec down / unusable verdict, fail-closed ban |
| `ban:captcha-downgrade` | Kind was captcha; this router served a ban page (unsubscribed / unpublished / invalid captcha client) |
| `captcha:decision-header` | Incoming `bouncerDecisionHeader` is `c` |
| `captcha:lapi` / `captcha:lapi:<origin>` | CrowdSec decision type captcha (same origin encoding) |
| `captcha:lapi-failure` | LAPI fail-closed captcha |
| `captcha:stream-unhealthy` | Stream fail-closed captcha |
| `captcha:appsec-failure` | AppSec fail-closed captcha |
| `captcha:appsec` | AppSec JSON `action: captcha` (envelope relay, not pkg/captcha) |
| `captcha:challenge` | AppSec bot-detection `action: challenge` with non-empty body |
| `captcha:solved` | 302 after a successful solve (token pass or second-tab captcha-form POST) |
| `error:client-disconnected` | Client gone during AppSec body copy |

No space after `:`.

### Origin encoding (LAPI third field only)

Third field is usage-metrics origin already returned by `LookupRemediation` / `LiveLookup` (`MetricsOrigin`). Do not persist CrowdSec `Decision.Scenario` except the existing lists rewrite.

Because `:` is the header separator, rewrite **only** the MetricsOrigin joiner: prefix `lists:` → `lists_` in the header field. Do not globally replace every colon. Examples: `crowdsec` → `ban:lapi:crowdsec`; `lists:firehol_level1` → `ban:lapi:lists_firehol_level1`. Empty origin omits the third field (`ban:lapi`). Strip CR/LF/TAB from origin before emit. Do not change `MetricsOrigin` or DecisionStore packing.

### Out of scope

- Writing the header on pass, bypass, trusted IP, failure-action passthrough, remap-to-pass, valid captcha gate cookie (later origin requests), widget-asset passthrough, disabled bouncer, startup 503
- Storing raw scenario on DecisionStore
- Changing usage-metrics labels
- Incoming `bouncerDecisionHeader` request-header feature
- New public config keys (reuse `bouncerRemediationHeadersCustomName`; empty still disables)

### Breaking

Existing values `ban` / `captcha` / `solved-captcha` / `error:client-disconnected` / raw AppSec action **change**. Operators who panel on those strings must update queries. Header stays off by default.

## Ground in this tree

Current writers: `pkg/bouncer/bouncer.go` (`handleBanServeHTTP` hardcodes `ban`; `handleAppsecResponseServeHTTP` copies `decision.Action`; `handleClientDisconnectedServeHTTP` uses `error:client-disconnected`); `pkg/captcha/captcha.go` (`captcha`, `solved-captcha`). Origins already exist in `pkg/lapi/client_metrics.go` (`OriginPlugin*` constants) and LAPI lookup origin. README documents the old values.

## Current (code)

- `pkg/configuration/configuration.go` — `BouncerRemediationHeadersCustomName` is a string; default `""` disables the header. No other public key names this response header.
- `pkg/bouncer/bouncer.go` `New` — copies that name onto `remediationCustomHeader`. Empty stays empty.
- `pkg/bouncer/bouncer.go` `handleBanServeHTTP` — when the name is set, `Header().Set` the value `"ban"`. The `reason` and `origin` arguments are used for the ban template (`RemediationReason`) and `recordDropped` only, not the header.
- `pkg/bouncer/bouncer.go` `handleClientDisconnectedServeHTTP` — when the name is set, writes const `remediationHeaderClientDisconnected` (`error:client-disconnected`). Does not `WriteHeader`.
- `pkg/bouncer/bouncer.go` `handleAppsecResponseServeHTTP` — when the name is set, writes `decision.Action` as-is (`captcha`, `challenge`, or any other non-allow action that reached relay).
- `pkg/captcha/captcha.go` `ServeHTTP` — `writeRemediationHeader(..., "captcha")` on the challenge page; `writeRemediationHeader(..., "solved-captcha")` on token-pass 302.
- `pkg/captcha/captcha.go` `WriteSolvedRedirect` — `writeRemediationHeader(..., "solved-captcha")` on second-tab captcha-form POST 302.
- `pkg/captcha/captcha.go` `writeRemediationHeader` — no-op when the name is empty.
- `pkg/bouncer/bouncer.go` `forcedDecisionKind` — incoming `bouncerDecisionHeader` trimmed `b` / `c` forces `BannedValue` / `CaptchaValue`. Forced `b` calls `handleRemediationServeHTTP` with `lapi.OriginPluginForcedDecision`. Header value is still `"ban"` or `"captcha"`.
- `pkg/bouncer/bouncer.go` `ServeHTTP` — `GetRemoteIP` error → `handleBanServeHTTP` with `OriginPluginTechGetRemoteFail`; `ipAddr == nil` → `handleBanServeHTTP` with `OriginPluginTechTrustIPFail`. Both write `"ban"`.
- `pkg/bouncer/bouncer.go` `ServeHTTP` — trusted IP (`clientPoolStrategy.Checker.ContainsIP`) calls `next.ServeHTTP` with no remediation header.
- `pkg/bouncer/bouncer.go` `ServeHTTP` — `!b.enabled` calls `next.ServeHTTP` with no remediation header.
- `pkg/bouncer/bouncer.go` `ServeHTTP` — `startupBlock` with a missing subscribed backend writes `503` and returns; no remediation header.
- `pkg/bouncer/bouncer.go` `ServeHTTP` / `applyLapiFailureAction` — LAPI unpublished (`subscribeLAPI && lapiClient == nil`) or live lookup fail uses `OriginPluginLapiFailure`; stream/alone miss + `!StreamHealthy` uses `OriginPluginTechStreamFail`. Fail-closed ban writes `"ban"`; fail-closed captcha writes `"captcha"` via `handleRemediationServeHTTP`; `passthrough` takes `passOrForcedCaptcha` (no header unless forced `c`).
- `pkg/bouncer/bouncer.go` `ServeHTTP` — cache `LookupRemediation` error that is not an allowed Redis-unreachable pass calls `banOrWarnForcedCaptcha` with `OriginPluginTechCacheFail` and writes `"ban"`.
- `pkg/lapi/client_lookup.go` `LookupRemediation` / `pkg/lapi/client_live.go` `LiveLookup` — return stored kind plus `MetricsOrigin` (or packed intern id). ServeHTTP remediates with that origin via `resolveDroppedOrigin` / `appliedLAPIRemediation`. Header still `"ban"` or `"captcha"`.
- `pkg/lapi/client_metrics.go` `MetricsOrigin` — CrowdSec `lists` + scenario becomes `lists:<scenario>`; other origins keep the CrowdSec origin string. `OriginPlugin*` constants label plugin-side drops.
- `pkg/decisionstore/memory.go` `pack` — intern overflow Warns `decisionstore:intern overflow` and packs origin id `0`. `pkg/decisionstore/pack.go` `unpackWord` returns empty origin name plus that id. `pkg/bouncer/bouncer.go` `resolveDroppedOrigin` with `originID == 0` returns `""`.
- `pkg/decisionstore/zzz_lookup_test.go` `TestLookupHitsRangeLetterOnlyStillBans` — a Range blob with only the kind letter returns empty origin. Stream Range upserts usually carry origin (`pkg/lapi/client_stream.go` `KindOriginString(kind, MetricsOrigin(...))`).
- `pkg/bouncer/bouncer.go` `applyAppsecServeHTTP` — `ActionBan` and empty-body `ActionChallenge` call `handleBanServeHTTP` (header `"ban"`, metrics origin `"appsec"`). Non-empty challenge and `ActionCaptcha` (empty body included) call `handleAppsecResponseServeHTTP` (header = raw action). AppSec unpublished / `Query` error (not captcha failure, not disconnect) fail-closed ban writes `"ban"` with `OriginPluginAppsecFailure`. `ErrFailureCaptcha` writes `"captcha"` with that same origin.
- `pkg/bouncer/bouncer.go` `handleRemediationServeHTTP` — captcha kind on `!subscribeCaptcha`, `captchaClient == nil`, or `!captchaClient.Valid` calls `handleBanServeHTTP` (header `"ban"`). Widget-asset path (`IsCustomResourceRequest`) and valid gate cookie (not form POST) call `handleNextServeHTTP` (no header).
- `pkg/bouncer/origin_based_decision_remap.go` `applyOriginBasedDecisionRemap` — remap-to-pass becomes `NoBannedValue` and takes the pass path (no header).
- `README.md` (See the verdict in access logs; `BouncerRemediationHeadersCustomName`) — documents values `ban` / `captcha` / `solved-captcha` / `error:client-disconnected` / raw AppSec `action`.
- Tests pin those strings: `pkg/bouncer/zzz_bouncer_test.go`, `pkg/bouncer/zzz_captcha_routing_test.go`, `pkg/captcha/zzz_routing_test.go`, `zzz_constructor_test.go`, `zzz_plugin_test.go`, `zzz_servehttp_request_path_test.go`, `tests/e2e/real/simple-bouncer.Tests.ps1`, `tests/e2e/real/captcha.Tests.ps1`, `tests/e2e/mock/scenarios/custom-ban-page/run.sh`.
- Live specs still name `solved-captcha` and `error:client-disconnected`: `openspec/specs/core_plugin_middleware_captcha-widget/spec.md`, `openspec/specs/core_plugin_middleware_captcha-routing/spec.md`, `openspec/specs/core_plugin_middleware_bouncer/spec.md`.

## Out of scope

Ticket list, confirmed on dest (do not take):

- Header on pass / bypass / trusted IP / failure-action passthrough / remap-to-pass / valid captcha gate cookie / widget-asset passthrough / disabled bouncer / startup 503 — those paths do not set `remediationCustomHeader` today (`pkg/bouncer/bouncer.go`).
- Persist CrowdSec `Decision.Scenario` on DecisionStore except the existing `MetricsOrigin` lists rewrite (`pkg/lapi/client_metrics.go`).
- Change usage-metrics label strings (`IncDropped` / `OriginPlugin*`).
- Change incoming `bouncerDecisionHeader` request-header matching (`forcedDecisionKind`).
- New public config keys.

Inferred extras (list, do not take):

- Change ban template, status, or `Cache-Control`.
- Change AppSec envelope copy except the remediation header value.
- Change captcha widget / gate-cookie / siteverify behavior except the header value on challenge and solved 302.
- Emit `allow: pass` or any header on a next/origin response.
- Rewrite `MetricsOrigin` or DecisionStore packing so the header can avoid the `lists:` → `lists_` encode.

## Unknowns

- Where the emit helper should live (one bouncer writer vs also `pkg/captcha` knowing structured values). Explore owns the shape.
- AppSec JSON `action` values other than `ban` / `captcha` / `challenge` (`pkg/appsec/query.go` only names those plus `allow`). Closed vocabulary has no row. Today relay copies the raw action.
- How often a live stream Range hit still has empty origin (letter-only blob vs `KindOriginString` with `MetricsOrigin`). Header rule is specified (`ban:lapi` / `captcha:lapi` when empty).
- Blast radius of README, live specs, unit tests, and e2e access-log assertions that pin the old strings. Explore owns the list.
- Whether operators who panel on `error:client-disconnected` must change queries (see Tensions).

## Tensions

- Breaking lists `error:client-disconnected` among values that **change**. Desired closed vocabulary keeps that exact string (`kind` `error`, `reason` `client-disconnected`). Operators matching the full string do not need a new query; operators matching a single-token `ban` / `captcha` / `solved-captcha` do.
- Ticket Ground says `handleBanServeHTTP` hardcodes `ban` for every ban page, including AppSec `action: ban` and empty-challenge fail-closed. Desired splits those into `ban:appsec` / `ban:appsec-challenge-empty` / `ban:captcha-downgrade` / failure reasons even though they share one writer today.
- `ipAddr == nil` after a successful `GetRemoteIP` uses metrics origin `plugin:tech_trustipfail` (`pkg/bouncer/bouncer.go`, log `ServeHTTP:parseClientIP`). Desired header collapses it with `GetRemoteIP` error as `ban:unparseable-request`. Metrics labels stay unchanged (out of scope).
