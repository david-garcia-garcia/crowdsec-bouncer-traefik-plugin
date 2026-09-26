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
