# Explore

## Concepts

```
  Client.New(isRedis, writeHost, readHosts)
           │
           ▼
     redisCache
       writer  *SimpleRedis     ── Init(writeHost)
       readers []*SimpleRedis   ── Init(each read host)
           │
           ▼
     nextReader() *SimpleRedis
       n==0 → writer
       else  → readers[counter%n]   same pointer as the slice slot

  SimpleRedis { mu sync.Mutex; idle []*pooledConn; ... }

  #381 copy (other project):
       var r SimpleRedis
       r.Init(...)
       readers = append(readers, r)   // copies mu  → go vet copylocks
```

**This tree (measured):** not the #381 snippet. `Client.New` allocates `&simpleredis.SimpleRedis{}` per host and appends the pointer. `nextReader` returns that pointer. `go vet ./pkg/cache/` is clean. `go test ./pkg/cache/` passed, including `Test_nextReader`.

**Gap:** `Test_nextReader` builds `redisCache` by hand. It does not call `Client.New`. The spec `core_cache_redis_in-tree-client` already requires pointer storage and has a `nextReader` scenario; it has no `Client.New` construction scenario.

## Decisions

- This fork is not affected by upstream #381 item 2 (value-copied Redis readers). Production `pkg/cache/cache.go` already holds `*SimpleRedis`. No production code change.
- Proof is a `Client.New` test: two read hosts → two distinct non-nil reader pointers, neither is the writer; `nextReader` returns those same pointers (reuse `indexOfReader`). That test fails if New aliases one client, stores nil, or `nextReader` returns a struct copy.
- Fold the new scenario into existing spec `core_cache_redis_in-tree-client`. Do not create a new spec leaf.
- Do not bump published simpleredis, do not change `MGet`/`GetMany`, do not touch operator config.

## Open questions

- Q: Is “this issue from another project” [maxlerebourg/crowdsec-bouncer-traefik-plugin#381](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/381) item 2 (keep redis readers by pointer)?
  Decision: assumed — yes; slug `verity-redis-reader` plus the mutex/readers copy matches that item. Proceed on that dump.
  By: explore

- Q: Is existing `Test_nextReader` enough proof, or must we add a `Client.New` test?
  Decision: resolved — add `Client.New` test. The ticket asked to add a test; `Test_nextReader` does not cover the #381 construction site.
  By: explore

- Q: Should we change `pkg/cache/cache.go` anyway (defense in depth)?
  Decision: assumed — no. Code already matches the desired pattern; Bound the ask is a regression test plus a spec scenario.
  By: explore
