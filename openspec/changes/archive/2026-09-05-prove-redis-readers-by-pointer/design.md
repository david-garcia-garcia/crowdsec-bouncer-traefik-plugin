## Context

Dest `master` already holds `writer *simpleredis.SimpleRedis` and `readers []*simpleredis.SimpleRedis`. `Client.New` allocates `&simpleredis.SimpleRedis{}` per host. `Test_nextReader` checks `nextReader` pointer identity on a hand-built `redisCache`. Upstream #381 is the value-copy construction (`append(readers, r)` after `var r SimpleRedis`).

FindSpecHost: fold into `core_cache_redis_in-tree-client` (small adjustment to an existing leaf). Confidence high. Candidates: `core_cache_redis_in-tree-client`.

## Goals / Non-Goals

**Goals:**
- A `Client.New` test that fails if readers are copied by value or aliased.
- Spec scenario for that construction site.

**Non-Goals:**
- Changing production `cache.go`.
- Published `simpleredis` bump, `MGet`, operator keys, go-redis, `useUnsafe`.
- Rewriting the stale “MGet is available without cache calling it” scenario (noted on destate/issues.md).

## Decisions

1. **Test through `Client.New`.** Type-assert `client.cache` to `*redisCache` in the test package (same package `cache`). Reuse `indexOfReader`.
2. **No production hunk.** Explore measured pointers + clean `go vet`. Bound the ask is the proof test.
3. **Two read hosts.** Distinct-pointer checks need at least two readers plus the writer.

## Risks / Trade-offs

- [Test imports redisCache internals] → Same package as `Test_nextReader`; no new export.
- [Hosts `127.0.0.1:1` / `:2` / `:3` never accept] → New does not dial; Close is safe (existing `Test_ClientCloseRedis`).

## Migration Plan

No operator config change. Rollback is revert.
