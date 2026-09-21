# Requirement
IssueKey: 2026-09-05-verity-redis-reader

## Problem
Upstream [maxlerebourg/crowdsec-bouncer-traefik-plugin#381](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/381) (item 2) says a pooled `SimpleRedis` holds `sync.Mutex`, so `pkg/cache` must not copy a client by value into `rc.readers` (go vet `copylocks`). This ticket is to ensure this fork is not affected; if it is not, prove it with a test that would fail if the copy returned.

## Current (code)
- `pkg/simpleredis/simpleredis.go` — `SimpleRedis` has `mu sync.Mutex` and `idle []*pooledConn`. Copying the struct after `Init` copies the lock.
- `pkg/cache/cache.go` `redisCache` — `writer *simpleredis.SimpleRedis`, `readers []*simpleredis.SimpleRedis`. `nextReader` returns `rc.readers[idx]` (or `rc.writer` when the slice is empty). Pointer type, not a value copy.
- `pkg/cache/cache.go` `Client.New` — allocates `&simpleredis.SimpleRedis{}` for the writer and each read host, `Init`, then `append` the pointer. Comment on that block: hold by pointer so the pool mutex is not copied. This is not the #381 snippet (`var r SimpleRedis` then `append(..., r)`).
- `pkg/cache/cache_test.go` `Test_nextReader` — pointer identity of `nextReader()` vs `rc.readers[i]` / writer, on a hand-built `redisCache`. It does not call `Client.New`.
- `knowledge/devdocs/core_cache_redis.md` — already: hold each client by pointer after `Init`; do not copy `SimpleRedis` by value after `Init`.
- `knowledge/research/ext_simpleredis_client_pooled-mget/notes.md` — Copy-by-value mutex section.

## Desired
Prove this tree is not affected by the #381 reader copy. If it is not, add a test that fails if `Client.New` or `nextReader` copies a pooled `SimpleRedis` by value (distinct `*SimpleRedis` per read host from `New`; `nextReader` returns those same pointers).

## Affected
- `pkg/cache/cache_test.go` (test to add)
- `pkg/cache/cache.go` only if the construction is actually a value copy (current tree is not)

## Out of scope
- Bumping published `github.com/maxlerebourg/simpleredis` (client is already in-tree `pkg/simpleredis`)
- Adding `MGet` or changing ranged-decision lookup (already `GetMany` / `MGet`)
- `Set`/`Del` error-surface follow-up from #381 item 3
- Operator Redis keys, `redisCacheReadHosts` config shape, go-redis, `useUnsafe`

## Unknowns
- The caller named “this issue from another project” without a URL. Slug `verity-redis-reader` plus the mutex/readers copy matches #381 item 2; that is the dump used here.
- Whether existing `Test_nextReader` is considered enough proof. The ticket asked to add a test; the construction site (`Client.New`) is not covered by that test.

## Tensions
- Usage docs and the `New` comment already state the invariant. The remaining product delta is a regression test, not a new cache behaviour.
- `Test_nextReader` already checks `nextReader` pointer identity. A `Client.New` test is the missing lock on the #381 construction snippet; it is not a second round-robin test.
