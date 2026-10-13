# Requirement
IssueKey: 2026-09-18-lapi-scope-failclosed-query-hardening

## Problem
Five defects, all inside the live-lookup and LAPI HTTP paths of `pkg/lapi`, extracted from open PR #30 and re-implemented on current master `0e7dbf0` (#30's serialization half already landed via #72; its remaining half predates #62's `transport` rework). Deliverable 1 is a security fix and a behavior change: a header-scope LAPI query that errors is reported to the caller as "this scope has no decision", so `none`/`live` mode allows the request and `crowdsecLapiFailureAction` never applies. Deliverable 2: `handleStreamCache` wins the `updated` lease and returns on a failed stream GET without releasing it, so nothing re-polls until the lease TTL expires. Deliverable 3: the alone-mode 401 retry re-issues a POST as a GET because it drops `data`. Deliverable 4: the response body is never closed when the status is 502/503/504, so the keep-alive slot leaks exactly while LAPI is behind an unhealthy reverse proxy. Deliverable 5: the same early return wraps a nil `err` with `%w`, so the operator sees `%!w(<nil>)` instead of the status that failed.

## Current (code)
- `mergeLiveScope` returns only `(string, time.Duration)`; a failed scope query logs at `Debug` and returns `chosen, parsedDuration` unchanged. `pkg/lapi/client_decisions.go:130-138`
- `handleNoStreamCache` calls it in a loop and keeps no error. `pkg/lapi/client_live.go:23-25`
- The IP query's error does propagate, so a fully-down LAPI is still handled. `pkg/lapi/client_live.go:19-22`
- `handleNoStreamCache` already uses a non-nil error to mean "banned": `errors.New("handleNoStreamCache:banned")`. `pkg/lapi/client_live.go:32-36`
- `pkg/bouncer` disambiguates by `decisionscope.IsActiveRemediation(kind)` before `applyLapiFailureAction`. `pkg/bouncer/bouncer.go:229-247`
- `crowdsecLapiFailureAction` accepts `passthrough`, `ban`, `captcha`; empty is `ban`; default is `ban`. `pkg/configuration/configuration.go:42-47,139-157,185`
- Package levels for a recoverable LAPI failure are `Warn` (`getToken statusCode`, `handleStreamTicker updateFailure`); terminal ones are `Error`. `pkg/lapi/client_http.go:191` `pkg/lapi/client_stream.go:58,62`
- README documents `CrowdsecLapiFailureAction` as "live/none HTTP or parse error, or a cache miss while stream/alone is unhealthy". It does not mention header-scope queries. `README.md:505-508`
- `handleStreamCache` acquires `updated` with TTL `max(updateInterval-1, 1)`, then `return err` on the stream GET without deleting the key. `pkg/lapi/client_stream.go:74-100`
- Later failures in the same function also return without releasing: JSON unmarshal. `pkg/lapi/client_stream.go:101-105`
- `cache.Client.Delete(key)` exists and reaches both backends (`localCache.delete` → `ttl_map.Del`; `redisCache.delete` → `writer.Del` on the prefixed key). `pkg/cache/cache.go:69-71,155-159,213-217`
- `crowdsecQuery` discards `data` on the alone-mode 401 retry: `return c.crowdsecQuery(stringURL, nil)`. `pkg/lapi/client_http.go:218-223`
- `getToken` itself calls `crowdsecQuery` on the CAPI login route, so a 401 on login recurses without bound today. `pkg/lapi/client_http.go:159-193`
- `defer res.Body.Close()` is installed after the early return, so a 502/503/504 returns with the body open. `pkg/lapi/client_http.go:209-217`
- `isReverseProxyError` is 502/503/504. `pkg/lapi/client_http.go:114-118`
- The same early return formats `%w` with a nil `err` when the status is the trigger. `pkg/lapi/client_http.go:210-212`
- Open PR #70 fixes the equivalent AppSec leak by moving `defer c.drainResponse(res)` above a separate `isReverseProxyError` check, and extends `Test_appsecQuery_reusesConnection` to 502/503/504. `pkg/appsec/query.go:106-121` on that branch; `drainResponse` on master is `pkg/appsec/query.go:179-187`
- No `errors.Join` anywhere in the tree; `pkg/lapi` returns a single error per call.
- Live-path tests exist: `Test_liveLookup_lapiErrorIsNotABan`, `TestLiveLookup_PerRouterTTLLastWrites`. `pkg/lapi/zzz_failure_action_test.go`
- Lease tests exist: `TestHandleStreamCacheIntervalOneStoresLease`, `TestHandleStreamCache_TwoMemoryPollersOneFetch`, `TestHandleStreamCache_TwoRedisPollersOneFetch`. `pkg/lapi/zzz_client_stream_test.go`
- Test seam is `attachTestTransport(client, httpClient, key)`. `pkg/lapi/zzz_session_test.go:39-41`

## Desired
- A scope-query failure SHALL reach `LiveLookup`'s caller and be treated exactly like an IP-query failure, so the operator's `crowdsecLapiFailureAction` decides. Required matrix, one test per row:
  - clean IP + all scopes succeed with no decision → allow, no error
  - clean IP + one scope errors → error surfaced with a **non-active** kind so the failure action applies
  - clean IP + one scope returns a ban → ban wins
  - active ban on IP + one scope errors → **ban wins**; the error must not downgrade or mask it
  - IP query errors → unchanged; the IP error propagates
  - clean IP + two scopes, one errors and one returns a ban → ban wins
- Keep the overloaded non-nil error intact: "banned" keeps coming back with an active remediation; a failure comes back with a non-active one. Make the distinction explicit in the code, not implicit.
- Raise the swallowed `Debug` to `Warn` (the level this package already uses for a recoverable LAPI failure).
- Document the behavior change in `README.md` next to `crowdsecLapiFailureAction`: scope-query failures now honour it, and `passthrough` restores the permissive behavior.
- Release the `updated` lease on every failure path in `handleStreamCache` that got past a won `Acquire`, so the next tick can retry immediately. Do not change the TTL or the acquire semantics.
- Replay the original request body on the alone-mode 401 retry, and bound the recursion so a second 401 cannot retry forever.
- Close the response body on the 502/503/504 path (same approach as #70: install the drain/close before the status check).
- Make the two early-return messages accurate: a transport error keeps `%w`; a reverse-proxy status names the status code and does not wrap a nil error. Assert the message text in a test.

## Affected
- `pkg/lapi/client_decisions.go` (`mergeLiveScope`)
- `pkg/lapi/client_live.go` (`handleNoStreamCache`)
- `pkg/lapi/client_stream.go` (`handleStreamCache` lease release)
- `pkg/lapi/client_http.go` (`crowdsecQuery`, `getToken`)
- `pkg/lapi/zzz_*_test.go` (new live-scope, lease-release, and query-hardening tests)
- `README.md` (`crowdsecLapiFailureAction` description only)
- `openspec/specs/core_plugin_lapi_failure-action/spec.md` and/or new leaves (propose decides the fold)
- `knowledge/devdocs/core_plugin_lapi_connection.md`, `knowledge/devdocs/core_plugin_lapi_stream-lease.md` if usage text must name the new invariants (devdocsimpact)

## Out of scope
- `pkg/cache`, `pkg/captcha`, `pkg/appsec`, `pkg/reclaim`, `pkg/ip`
- `pkg/bouncer` unless deliverable 1 genuinely cannot be done in `pkg/lapi` alone
- The reclaim design and the stream lease *design* (`Acquire`, `updated`, the TTL floor)
- The three existing debt notes in `knowledge/debt/`
- Undoing or duplicating #72's `streamPollInFlight` CAS, the three `int64` health flags, or `startTicker`'s inline `work()`
- Closing, commenting on, or modifying #30, #42, or #70; touching #70's branch
- The release workflows and the stale `main` branch
- A `res == nil` guard on `crowdsecQuery` (`||` short-circuits; `net/http` guarantees a non-nil response when `err == nil`)

## Unknowns
- Whether a JSON-unmarshal or apply failure later in `handleStreamCache` should also release the lease.
- Whether the negative live cache entry should still be written for `remoteIP` when a scope query failed.

## Tensions
- Ticket line numbers match dest `0e7dbf0` exactly for every hunk quoted.
- The ticket demands a louder log *and* error propagation for the same event, so a flaky scope path now emits one `Warn` per request. Accepted: the ticket makes the level explicit.
- `mergeLiveScope`'s signature must grow an error, which is a behavior-relevant API change inside an unexported method — no public surface moves.
- No Task subagent is used in this run (this session is itself a subagent); prepare and code review are executed in-process. Note it on the card.
