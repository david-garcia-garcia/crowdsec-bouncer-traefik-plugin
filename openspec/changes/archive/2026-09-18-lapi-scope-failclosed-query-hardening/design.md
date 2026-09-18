## Context

See `proposal.md` Why. Baseline is `master` `0e7dbf0`. Facts measured on that tree (throwaway `TestScratch*` file, removed after the run — see `devstate/2026/09/2026-09-18-lapi-scope-failclosed-query-hardening/explore.md`):

- `mergeLiveScope` (`pkg/lapi/client_decisions.go:130`) returns `(string, time.Duration)`; a scope error logs `Debug` and returns the caller's verdict unchanged. `LiveLookup` then returns `("f", nil)` and the bouncer allows.
- `pkg/bouncer` separates "banned" from "LAPI failed" on the **remediation kind** (`decisionscope.IsActiveRemediation`), not on the error (`pkg/bouncer/bouncer.go:229-247`). The non-nil error is already overloaded (`handleNoStreamCache:banned`).
- `handleStreamCache` (`pkg/lapi/client_stream.go:74`) returns after a failed GET while holding `updated`; `cacheClient.Get("updated")` still succeeds.
- `crowdsecQuery` (`pkg/lapi/client_http.go:195`) installs `defer res.Body.Close()` after the `err != nil || isReverseProxyError(...)` return; ten calls against a 502 opened ten connections. The same return formats `%w` over a nil `err`.
- The 401 retry passes `nil` for `data`; a POST came back as a GET. `getToken` calls `crowdsecQuery` on the CAPI login route, so a 401 there recurses without bound today.
- `.golangci.yml` is `enable-all` with `nonamedreturns` live. `errors.Join` appears nowhere in the tree.
- Sibling: open PR #70 fixes the identical AppSec drain by moving `defer c.drainResponse(res)` above a separate `isReverseProxyError` check and extending `Test_appsecQuery_reusesConnection` to 502/503/504. `pkg/appsec/query.go:179-187` already has `drainResponse`.

FindSpecHost:

```
verdicts:
  - { deltaId: header-scope-fail-closed, fold|new: fold, spec-id: core_plugin_lapi_failure-action, confidence: high, candidates: [core_plugin_lapi_failure-action, core_plugin_lapi_scope-union, core_plugin_lapi_connection] }
  - { deltaId: stream-lease-release-on-failure, fold|new: fold, spec-id: core_plugin_lapi_stream-lease, confidence: high, candidates: [core_plugin_lapi_stream-lease, core_plugin_lapi_stream-single-flight] }
  - { deltaId: lapi-query-round-trip, fold|new: new, spec-id: core_plugin_lapi_query-round-trip, confidence: high, candidates: [core_plugin_lapi_connection, core_plugin_appsec_client, core_plugin_lapi_query-round-trip] }
```

Search: family `core_plugin_lapi` holds `failure-action` (already the owner of "live LAPI error uses CrowdsecLapiFailureAction" — the scope hole is a two-requirement adjustment to that contract, not a new capability), `stream-lease` (owner of `updated` / `Acquire` — release-on-failure is one requirement on that same key), `scope-union` (stream `scopes=` construction, not the live per-request query), and `connection` (reclaim ownership, file layout, transport replacement, log levels — not the round trip). The round-trip contract has no owner in this family; `pkg/appsec` splits the same concern into `core_plugin_appsec_client`, so the LAPI twin gets its own leaf rather than being stuffed into `connection`.

## Goals / Non-Goals

**Goals:**

- A header-scope query failure reaches `LiveLookup`'s caller and is treated exactly like a client-address query failure.
- An active remediation is never downgraded or masked by a scope failure.
- A poll that wins the stream lease and fails releases it, from one code site.
- A token renewal replays method and body, bounded.
- Every answered LAPI response is drained and closed; every failure message names its own cause.

**Non-Goals:**

- Changing the stream lease design (`Acquire`, `updated`, the TTL floor) or the `!won` branch.
- Touching `pkg/bouncer`, `pkg/cache`, `pkg/captcha`, `pkg/appsec`, `pkg/reclaim`, `pkg/ip`.
- Undoing or duplicating #72's `streamPollInFlight` CAS, `int64` health flags, or inline `startTicker` work.
- A `res == nil` guard in `crowdsecQuery`.
- A new error type, sentinel, or `errors.Join` aggregation.
- New public config keys.

## Decisions

1. **`mergeLiveScope` returns `(string, time.Duration, error)`.** On a query error it returns the caller's verdict unchanged plus that error, and logs at `Warn` — the level this package already uses for a recoverable LAPI failure (`getToken statusCode`, `handleStreamTicker updateFailure`). Alternative: an out-parameter or a struct result — rejected, three returns is the package idiom and the caller needs both halves.
2. **`handleNoStreamCache` keeps the first scope error and checks `IsActiveRemediation(chosen)` first.** Active → cache and return `(chosen, errors.New("handleNoStreamCache:banned"))`, unchanged. Non-active with a scope error → `("", scopeErr)`, the exact shape a client-address failure already returns, and **no** negative cache write. Non-active with no error → unchanged. Alternative: `errors.Join` of every scope error — rejected, absent from this tree and `pkg/lapi` returns one error per call; the `Warn` line already names each failing scope.
3. **The overloaded error is documented, not re-encoded.** A doc comment on `LiveLookup` states the contract: active remediation + error means banned; non-active remediation + error means LAPI failed. A sentinel or error type would be a second classifier for a fact the remediation kind already carries (`skill:sbs-dev-commandments:One job, one owner`).
4. **Lease release has one site.** The fetch+apply body of `handleStreamCache` moves into `fetchAndApplyStreamDecisions`; `handleStreamCache` owns the lease and calls `c.Cache().Delete(cacheTimeoutKey)` on any error from it. `Delete` reaches both backends (`localCache.delete` → `ttl_map.Del`; `redisCache.delete` → `writer.Del` on the prefixed key). Alternative: a named-return `defer` — rejected, `nonamedreturns` is enabled. Alternative: a `Delete` at each failure site — rejected, it would let the GET and the decode stages diverge.
5. **Token-renewal permission is threaded, not counted.** `crowdsecQuery(url, data)` delegates to `sendQuery(url, data, mayRenewToken=true)`; the replay passes `false`; `getToken` passes `false` so a 401 on the CAPI login route cannot recurse at all. Alternative: an attempt counter — rejected, the permission is the real invariant and it also closes the pre-existing login recursion.
6. **`drainResponse` mirrors its AppSec sibling** (same body, same `crowdsecQuery:drainBody` / `crowdsecQuery:closeBody` log shape) and is deferred immediately after the transport-error check, with the `isReverseProxyError` check moved below it. Close-only would not return the connection to the idle pool, so it would not fix the leak.
7. **Messages split.** Transport error keeps `crowdsecQuery:unreachable url:%s %w`. Reverse-proxy status becomes `crowdsecQuery:unreachable url:%s statusCode:%d`. The `unreachable` prefix stays because operators grep it and AppSec logs the same string for the same condition (`skill:sbs-dev-commandments:Symmetry and consistency`).
8. **README** extends the `CrowdsecLapiFailureAction` description with the header-scope clause and names `passthrough` as the way back to permissive.

## Risks / Trade-offs

- [Behavior change for existing deployments] → A flaky scope path that silently allowed now applies `crowdsecLapiFailureAction`, default `ban`. Documented in README, surfaced on the PR body with the full matrix, and left for owner ratification. Not merged by this run.
- [One `Warn` per failed scope query, at request rate] → Accepted; the ticket makes the level explicit and the alternative is the silent allow this change exists to remove.
- [`fetchAndApplyStreamDecisions` is a new function on a hot path] → No behavior moves with it; it also brings `handleStreamCache` back under the `funlen` statement budget.
- [Dropping the negative cache write on a scope failure adds LAPI load while a scope path is broken] → Accepted; caching an unverified allow is the defect.

## Migration Plan

No public JSON/YAML key changes. Operators who relied on the silent allow set `crowdsecLapiFailureAction: passthrough`. Rollback is revert.
