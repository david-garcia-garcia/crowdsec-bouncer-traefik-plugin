## Why

On DestBranch a header-scope LAPI query that errors is reported as "this scope has no decision", so `live`/`none` requests are allowed and `crowdsecLapiFailureAction` never applies. The only trace is a `Debug` line. Four defects on the same two code paths: the stream lease is kept after a failed poll, the alone-mode 401 retry drops the request body, a 502/503/504 answer leaves the response body unclosed, and that same return wraps a nil error with `%w`.

## What Changes

- **Deliverable 1 (SECURITY, behavior change).** `mergeLiveScope` returns `(string, time.Duration, error)`. `handleNoStreamCache` keeps the first scope error, checks `IsActiveRemediation` first so an active ban always wins, and otherwise returns `("", scopeErr)` — the same shape an IP-query failure already returns — so `crowdsecLapiFailureAction` applies. The swallowed `Debug` becomes `Warn`. No negative live cache write when a scope query failed. `README.md` documents the new operator-visible behavior next to `crowdsecLapiFailureAction`.
- **Deliverable 2.** `handleStreamCache` releases the `updated` lease on every failure past a won `Acquire` by deleting that key, so the next tick re-polls immediately. The fetch+apply body moves into `fetchAndApplyStreamDecisions` so the release has one site. `Acquire`, the TTL floor, and the `!won` branch are unchanged.
- **Deliverable 3.** The alone-mode 401 retry replays the original method and body. `crowdsecQuery` delegates to `sendQuery(url, data, mayRenewToken)`; the replay clears that permission and `getToken` never grants it, so a second 401 cannot recurse.
- **Deliverable 4.** `drainResponse` is added to `pkg/lapi` (same body and log strings as its AppSec sibling) and deferred immediately after the transport-error check, so 502/503/504 responses are drained and the keep-alive slot is reused.
- **Deliverable 5.** The transport-error branch keeps `%w`; the reverse-proxy-status branch names `statusCode:%d` and does not wrap a nil error.

## Capabilities

### New Capabilities

- `core_plugin_lapi_query-round-trip`: the LAPI/CAPI HTTP round trip — token-renewal replay, response drain, and accurate failure messages.

### Modified Capabilities

- `core_plugin_lapi_failure-action`: header-scope query failures now reach the caller as a LAPI failure and honour `crowdsecLapiFailureAction`; an active remediation still outranks a scope failure.
- `core_plugin_lapi_stream-lease`: a poll that wins the lease and then fails releases it.

## Impact

- `pkg/lapi/client_decisions.go`, `pkg/lapi/client_live.go`, `pkg/lapi/client_stream.go`, `pkg/lapi/client_http.go`
- `pkg/lapi/zzz_failure_action_test.go`, `pkg/lapi/zzz_client_stream_test.go`, new `pkg/lapi/zzz_client_http_test.go`
- `README.md` (`crowdsecLapiFailureAction` description only)
- **Behavior change:** a deployment whose header-scope path silently allowed will now apply `crowdsecLapiFailureAction`, whose default is `ban`. `passthrough` restores the permissive behavior. No public JSON/YAML key changes.
- Out of scope: `pkg/cache`, `pkg/captcha`, `pkg/appsec`, `pkg/reclaim`, `pkg/ip`, `pkg/bouncer`; the reclaim design; the stream lease design (`Acquire`, `updated`, the TTL floor); #72's `streamPollInFlight` CAS, `int64` health flags, and inline `startTicker` work; a `res == nil` guard in `crowdsecQuery`; closing, commenting on, or modifying #30, #42, or #70; the release workflows and the stale `main` branch
