# Proposal

## Why

With `bouncerRemediationStatusCode: 429`, a ban from a CrowdSec LAPI decision is answered 429 with no `Retry-After`. A client that honours 429 cannot tell when to come back, although the bouncer knows when the decision ends. Upstream proposes the header in maxlerebourg/crowdsec-bouncer-traefik-plugin#439 (open). This fork's decision store and serve paths differ from upstream's, so the fork builds it on its own units.

## What Changes

- A ban answered 429 that comes from a LAPI decision with a known end carries `Retry-After`: the seconds left on that decision, rounded up, at least 1 (RFC 9110 delay-seconds). The header is set before `WriteHeader`, so a HEAD ban carries it too.
- No `Retry-After` when the written status is not 429. None on an AppSec ban, even with AppSec `http_status` 429. None on a ban that no LAPI decision is behind: a LAPI, AppSec, or ModSecurity failure action, the cache-failure ban, an unhealthy stream, an action-rule `ban`, or a `captcha` rule served as a ban.
- A LAPI captcha decision served as a ban (router without a captcha, or captcha client not usable) is still a LAPI decision, so it gets the header. A captcha `bouncerActionRules` row that loses to a LAPI ban also gets it. A challenge page never gets it.
- Several hits: the end of the decision the lookup chose (ban over captcha, first hit on a tie).
- stream/alone: the end comes from the stored decision. Range-scope bans served from the Range index carry no header: that blob has no end. In live/none, LAPI expands Range on the `?ip=` query and returns the decision's duration, so a Range ban there gets the header like any LAPI ban (`devstate` deviation, taken in explore).
- live: a cached ban reports the decision's real end, not the cache-entry end. The cache entry still lasts at most `lapiDefaultDecisionSeconds`.
- Memory slot: each in-memory decision grows from 8 to 12 bytes (a decision-end field). Approved by the requester. Measured in explore: map storage +50 %, about 26.7 → 33.7 MB for 400k decisions with keys; key lookup unchanged.
- Redis slot value: a 4th line, the decision end in wall-clock Unix seconds, after `kind`, `origin`, and `scenario`. Fork versions from v1.9.4 read it as part of the scenario, which their lookup never returns, so a rolling upgrade and a rollback keep reading kind and origin. A value without the field (written by an older instance) gives no header until it expires.
- README documents the header next to `bouncerRemediationStatusCode`, with the Range and rolling-upgrade exceptions.
- **Not BREAKING.** With `bouncerRemediationStatusCode` 403 (the default) responses are unchanged.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_bouncer`: new requirement "A LAPI ban answered 429 carries Retry-After"; "Live stream and alone lookup uses one Store entry" names the time left that `LookupRemediation` and `LiveLookup` return.
- `core_plugin_decisionstore_store`: new requirement "Store lookup returns the winning decision's time left" (12-byte memory slot, Redis end field, decision duration kept apart from the store TTL); "DecisionStore owns the origin intern table" and "DecisionStore interns the raw LAPI scenario" state the real Redis slot value (kind, origin, scenario, end) instead of `KindOriginString`, the 12-byte slot, and the lookup return.
- `core_plugin_decisions_scopes`: "Remediation values carry kind then origin" states the Redis slot value; "Live IP cache slot is the IP query result" names the `LiveLookup` return.
- `core_plugin_lapi_stream-apply`: "Stream apply writes deleted before new" — the Redis scenario names the slot value with its end.

## Impact

- `pkg/decisionstore`: `liveslot.go`, `decision.go`, `memory.go`, `memory_pack.go` (comment table), `redis.go`, `redis_pack.go`, `lookup.go`, `store.go`
- `pkg/lapi`: `client_lookup.go`, `client_live.go`, `client_decisions.go`
- `pkg/bouncer`: `bouncer_serve_lapi.go`, `bouncer_serve_remediation.go`, `bouncer_serve_captcha.go`, `bouncer.go`, `bouncer_serve_appsec.go`, `bouncer_serve_appsec_verdict.go`, `bouncer_serve_modsec.go` (callers pass "no decision end")
- Tests in `pkg/decisionstore`, `pkg/lapi`, `pkg/bouncer`, and root `zzz_plugin_test.go` (lookup return shape); benchmarks in `pkg/decisionstore`
- `tests/e2e/mock` (stream, live, redis scenarios; mock Redis canned value), `tests/e2e/real` (`simple-bouncer.Tests.ps1` `/status-429`, a stream 429 router)
- `README.md`; devdocs `core_plugin_decisionstore.md`, `core_plugin_middleware_ban-page.md`, `core_plugin_lapi_stream-apply.md`
- Shared Redis: slot values gain one field; key names and TTLs are unchanged.
