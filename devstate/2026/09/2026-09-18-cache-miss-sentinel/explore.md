# Explore
IssueKey: 2026-09-18-cache-miss-sentinel

## Concepts

**Stream allow miss** is the common high-traffic path on dest: stream (or alone) + in-memory DecisionStore, no `f` Ip slot, `LookupCachedRemediation` returns miss, then `StreamHealthy` allow. Stream apply `storeStreamDecision` Sets only ban/captcha; it never Sets `NoBannedValue` (`f`) for clean IPs (`pkg/lapi/client_decisions.go`). Live `cacheLiveScope` does store `f`. Storing negatives for all IPs is out of scope.

**Miss-as-error** is dest’s encoding of “no slot”: `CacheMiss` / `CacheUnreachable` are string constants (`pkg/cache/cache.go`). `localCache.get` and `LookupCachedRemediation` each `errors.New(CacheMiss)` on a clean miss. `ServeHTTP` then does `cacheErr.Error()` and string-equals those constants (`pkg/bouncer/bouncer.go`).

Dest path for a clean stream request (no header scopes):

```
ServeHTTP
  → LookupCachedRemediation
       → Client.GetMany([ip])          // slog Debug + fmt.Sprintf (out of scope)
            → localCache.get(ip)       // errors.New(CacheMiss) per absent key
            → omit key from map        // GetMany still succeeds
       → no active rem; Ip key absent
       → errors.New(cache.CacheMiss)   // second miss error
  → cacheErr.Error() == CacheMiss → break
  → StreamHealthy → allow
```

Vendored SimpleRedis already owns package sentinels (`ErrMiss`, `ErrUnreachable`) plus `IsMiss` / `IsUnreachable`. `pkg/cache` redis `get` maps those into a **new** `errors.New(CacheMiss)` / `errors.New(CacheUnreachable)` instead of a package sentinel.

**Reproduced** this explore (throwaway bench, then deleted; Windows amd64, ERROR logger):

| Path | ns/op | B/op | allocs/op |
| --- | --- | --- | --- |
| `LookupCachedRemediation` miss | 175 | 184 | 7 |
| `Client.Get` miss | 65 | 64 | 3 |

Ticket numbers (249 ns / 200 B / 9 allocs lookup; 524 ns / 408 B / 17 allocs full stream allow) are the same direction on a different machine. Full `ServeHTTP` stream allow was not re-measured (needs a bouncer harness). About half the lookup miss cost is the two `errors.New` plus the GetMany map/keys.

Sibling string-eq sites that must switch to `errors.Is` or sentinels will not compose: `localCache.acquire`, `readRangeIndex`, `hydrateRangeMembership`, Redis `get`/`getMany`/`acquire`. Existing tests assert `err.Error() == CacheMiss`.

This work does not reconstruct client address, user, tenant, Host, or trust hop. No Traefik `New` / reclaim / `sync.Once` change. DecisionStore already owns the cache (`core_cache_client.md`).

Spec host today: `core_cache_client_decision-store` says store errors SHALL remain `CacheMiss` and `CacheUnreachable` (the string constants). Propose FindSpecHost: fold a miss-sentinel requirement onto that leaf (or a sibling `core_cache_client_*`), not a new family.

Usage: `core_cache_client.md` is enough to Open/Get/Set. After apply, implementers match miss with `errors.Is(..., cache.ErrMiss)` — a usage gotcha to add then, not now.

No third-party research write: Go `errors.Is` is stdlib; Redis protocol is out of scope; SimpleRedis sentinels are already documented on `core_cache_redis.md`.

## Decisions

- Bound: package-level sentinels + `errors.Is` at callers. Do not store stream negatives, change Redis protocol, stream apply, Range radix, lazy slog, Redis pool, AppSec, or `ttl_map`.
- `pkg/cache` exports `ErrMiss` and `ErrUnreachable` as `errors.New` of the existing `CacheMiss` / `CacheUnreachable` strings. Keep the string constants so `Error()` text stays `cache:miss` / `cache:unreachable`.
- `localCache.get`, Redis `get`/`getMany`, and `LookupCachedRemediation` return those vars (no `errors.New` per miss). GetMany still omits missing keys.
- Callers (`ServeHTTP`, `acquire`, `readRangeIndex`, `hydrateRangeMembership`) use `errors.Is`. Tests switch to `errors.Is`.
- Redis modes return the same sentinels when `simpleredis.IsMiss` / `IsUnreachable`. Mapping is not a protocol change.
- `acquire` nil-client / bad Lua reply uses `ErrUnreachable` (same comparable error, not a new string).
- Do not wrap `ErrMiss` in `fmt.Errorf` on the lookup return (that would re-allocate and still need `%w`).

## Open questions

- Q: Do `CacheMiss` / `CacheUnreachable` strings stay as the sentinels’ `Error()` text?
  Decision: assumed — keep both string constants; `ErrMiss` / `ErrUnreachable` wrap those exact texts.
  By: explore

- Q: Must Redis `get` / `getMany` return the same package sentinels?
  Decision: assumed — yes. `errors.Is` is the public match; skipping Redis would break Redis modes. Not a wire-protocol change.
  By: explore

- Q: What is the unreachable sentinel name?
  Decision: assumed — `ErrUnreachable`, matching ticket `ErrMiss` and vendored SimpleRedis.
  By: explore

- Q: Does `LookupCachedRemediation` return `cache.ErrMiss` directly or `errors.New(cache.CacheMiss)`?
  Decision: assumed — return `cache.ErrMiss` so the second miss alloc is gone and `errors.Is` matches without unwrap.
  By: explore

- Q: Are ticket alloc numbers the gate?
  Decision: resolved — reproduced miss-as-error allocations (lookup 7 allocs / 184 B; Get 3 allocs / 64 B). Gate is zero new `errors.New` on a clean in-memory miss, not matching the ticket’s machine numbers.
  By: explore
