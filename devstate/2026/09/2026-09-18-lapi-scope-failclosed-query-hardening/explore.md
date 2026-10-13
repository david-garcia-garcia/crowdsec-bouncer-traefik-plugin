# Explore
IssueKey: 2026-09-18-lapi-scope-failclosed-query-hardening

## Concepts

Two paths on DestBranch `0e7dbf0`, five defects.

**Live lookup (deliverable 1).** `pkg/bouncer` calls `LiveLookup(remoteIP, scopes, defaultDecisionSeconds)` on every `live`/`none` cache miss. `handleNoStreamCache` queries LAPI once for `ip=`, then once per mapped header scope. The return contract is already overloaded: a non-nil error means either "banned" or "LAPI failed", and `pkg/bouncer` separates them by `decisionscope.IsActiveRemediation(kind)` before `applyLapiFailureAction` (`pkg/bouncer/bouncer.go:229-247`). `mergeLiveScope` cannot participate: its signature is `(string, time.Duration)`, so a failed scope query is indistinguishable from "no decision on this scope".

```
LiveLookup
  ├─ queryLiveDecisions ip=          err ──► ("", err)            non-active kind ──► FailureAction   [dest OK]
  └─ mergeLiveScope scope=&value=    err ──► Debug, verdict kept ──► ("f", nil) ──► allow             [dest BUG]
```

**LAPI HTTP round trip (deliverables 3, 4, 5).** `crowdsecQuery` is the single LAPI/CAPI request helper, on top of #62's `transport` snapshot (`currentTransport()`, `http.Client{Timeout: HTTPTimeoutSeconds}`). Three defects sit in it: the alone-mode 401 retry passes `nil` for `data`; the `defer` that closes the response body is installed *after* the `err != nil || isReverseProxyError(...)` early return; and that same return formats `%w` over a nil `err`.

```
Do(req)
  ├─ err                    ──► "unreachable ... %w err"     [body: none]
  ├─ 502/503/504            ──► "unreachable ... %!w(<nil>)" [body: NEVER closed  ── dest BUG x2]
  ├─ 401 + alone            ──► getToken, replay as GET      [body dropped ── dest BUG]
  ├─ non-2xx                ──► status error                 [drained by the defer]
  └─ 2xx                    ──► io.ReadAll
```

There is **no** nil-pointer bug on that line: `||` short-circuits, so `res.StatusCode` is only read when `err == nil`, where `net/http` guarantees a non-nil response. A previous review claimed a panic there and was wrong. Do not add a `res == nil` guard.

**Stream lease (deliverable 2).** `handleStreamCache` acquires `updated` with TTL `max(updateInterval-1, 1)` (`core_plugin_lapi_stream-lease`), then `return err` on a failed GET while still holding it. With the default `UpdateMaxFailure=0` the stream is already unhealthy after that first failure, so stream/alone cache misses take `CrowdsecLapiFailureAction` (default `ban`) for the rest of the lease window, and no instance re-polls.

Open PR #70 fixes the identical drain defect on the AppSec side by moving `defer c.drainResponse(res)` above a separate `isReverseProxyError` check and extending `Test_appsecQuery_reusesConnection` to 502/503/504. `pkg/appsec` already has `drainResponse` (`io.Copy(io.Discard)` then `Close`, `pkg/appsec/query.go:179-187`). Mirror that name and that test shape in `pkg/lapi` so the siblings match.

#72 landed the `streamPollInFlight` CAS at the top of `handleStreamTicker`, the three health flags as `int64` + `sync/atomic`, and `startTicker` calling `work()` inline. Two async spawn sites stay on purpose (`client_stream.go:41`, `client.go:227`). Nothing here touches any of that.

No `errors.Join` anywhere in the tree; every `pkg/lapi` call returns a single error. `.golangci.yml` is `enable-all` with `nonamedreturns` live, so a named-return `defer` cannot be the lease-release mechanism.

Consumed: `core_plugin_lapi_connection.md` (transport is `atomic.Value`, no `atomic.Pointer[T]`; `LiveLookup` takes the TTL from the caller), `core_plugin_lapi_stream-lease.md` (caller owns the TTL floor; do not Get-then-Set), `core_plugin_appsec.md` (drain wording). No new research needed: every fact is in-tree or in #70.

**Reproduced** (`go test ./pkg/lapi/ -run TestScratch -count=1`, throwaway file removed after the run, dest `0e7dbf0`):

1. Scope error silently allows — `LiveLookup("1.2.3.4", {"country":"FR"}, 60)` against a LAPI that answers `ip=` with `null` and 500s on `scope=` returned `value="f" err=<nil>`. `"f"` is `decisionscope.NoBannedValue`, so `pkg/bouncer` allows.
2. Lease held after a failed stream GET — `handleStreamCache` returned an error and `cacheClient.Get("updated")` still succeeded.
3. Token retry drops the body — request log was `methods=[POST GET] bodies=[{"payload":"keep-me"} ""]`.
4. Reverse-proxy status leaks the connection — 10 `crowdsecQuery` calls against a 502 opened **10** connections (want 1).
5. Nil error wrapped with `%w` — message was `crowdsecQuery:unreachable url:http://127.0.0.1:64508/v1/decisions %!w(<nil>)`, with no status code.

## Decisions

- `mergeLiveScope` grows a third return value, `error`. It returns the caller's current verdict unchanged plus the query error, and logs at `Warn` (the level this package already uses for a recoverable LAPI failure: `getToken statusCode`, `handleStreamTicker updateFailure`). Not `Error` — that level is for terminal/unhealthy transitions here.
- `handleNoStreamCache` keeps the **first** scope error and checks `IsActiveRemediation(chosen)` **first**, so an active ban always wins and always returns with the existing `handleNoStreamCache:banned` error. A non-active verdict plus a scope error returns `("", scopeErr)` — byte-for-byte the shape an IP-query failure already returns. No `errors.Join`: the package returns one error per call.
- Make the overloaded error explicit in a doc comment on `LiveLookup` rather than encoding it in a new type. The caller (`pkg/bouncer`) already discriminates on the remediation kind; a new sentinel or error type would be a second classifier for a fact the kind already carries.
- Do **not** write the negative live cache entry for `remoteIP` when a scope query failed. Caching `NoBannedValue` after an unverified scope would keep allowing for `defaultDecisionSeconds` even after LAPI recovers, and would contradict the error we just returned.
- Lease release: extract the fetch+apply body into `fetchAndApplyStreamDecisions` so `handleStreamCache` owns the lease and has exactly one release site (`c.Cache().Delete(cacheTimeoutKey)`). `Delete` reaches both backends (`localCache.delete` → `ttl_map.Del`; `redisCache.delete` → `writer.Del` on the prefixed key). TTL, `Acquire`, and the `!won` branch are untouched.
- Bound the 401 recursion by threading permission, not by counting: `crowdsecQuery` delegates to `sendQuery(url, data, mayRenewToken=true)`; the replay passes `false`; and `getToken` calls `sendQuery(..., false)` so a 401 on the CAPI login route cannot recurse at all. Dest recurses without bound there today.
- Add `drainResponse` to `pkg/lapi` with the same body and log strings as its AppSec sibling, and `defer` it immediately after the transport-error check. Closing without draining would not return the connection to the idle pool, so a close-only fix would not fix the leak the ticket names.
- Reverse-proxy status keeps the `crowdsecQuery:unreachable` prefix (operators grep it; AppSec logs the same string for the same condition) and gains `statusCode:%d`. The transport-error branch keeps `%w`.
- Spec hosts (FindSpecHost, one verdict per delta): `fold` `core_plugin_lapi_failure-action` (deliverable 1), `fold` `core_plugin_lapi_stream-lease` (deliverable 2), `new` `core_plugin_lapi_query-round-trip` (deliverables 3-5).
- Change name: `lapi-scope-failclosed-query-hardening`.

## Open questions

- Q: Should a failure after the GET in the same function (JSON unmarshal, range apply) also release the stream lease?
  Decision: resolved — yes. The lease means "this tick owns the fetch"; a poll that did not finish leaves the store un-updated whatever stage it died at, and the next tick should retry. The extraction gives one release site, so both stages behave the same instead of diverging.
  By: explore

- Q: Should the negative live cache entry for `remoteIP` still be written when a scope query failed?
  Decision: resolved — no. It would persist the silent allow for `defaultDecisionSeconds` past LAPI recovery, and contradict the error returned on the same call. The ban path still caches, unchanged.
  By: explore

- Q: How should several failing scopes be aggregated?
  Decision: resolved — keep the first error. `errors.Join` exists in Go 1.20 but appears nowhere in this tree, and `pkg/lapi` returns a single error per call. The `Warn` line names the scope, so all of them are still visible in the log.
  By: explore

- Q: Do deliverables 3-5 fold into `core_plugin_lapi_connection`?
  Decision: resolved — no. That leaf owns reclaim ownership, file layout, transport replacement, and log levels. Retry-replay, drain, and message accuracy are the round-trip contract; new leaf `core_plugin_lapi_query-round-trip`. AppSec splits the same way (`core_plugin_appsec_client` vs `core_plugin_appsec_failure-action`).
  By: explore

- Q: Who already owns identity on these paths (client address, header-scope value)?
  Decision: assumed — untouched. `pkg/bouncer` already resolved the client address via `pkg/ip` and passes `remoteIP` plus the `scopes` map into `LiveLookup`. This change never re-derives either. Do not read `RemoteAddr` here.
  By: explore

- Q: Does the deliverable 1 behavior change need owner sign-off before merge?
  Decision: blocked — the owner must ratify. A deployment with a flaky scope path that silently allowed will now apply `crowdsecLapiFailureAction`, whose default is `ban`. Implement it as specified and surface the matrix on the PR body; do not merge.
  By: explore
