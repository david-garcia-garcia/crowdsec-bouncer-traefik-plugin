## Why

On `master`, pooled `SimpleRedis` readers are already held by pointer, but `Test_nextReader` never calls `Client.New`. Upstream [crowdsec-bouncer-traefik-plugin#381](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/381) copies a pooled client by value (go vet `copylocks` on `sync.Mutex`). Without a construction-site test, that pattern can return here unnoticed.

## What Changes

- Add a `Client.New` unit test that fails if Redis writer/readers are aliased, nil, or value-copied.
- Add a spec scenario on `core_cache_redis_in-tree-client` for that construction site.
- Do not change production `pkg/cache/cache.go` (already pointer-safe).
- Do not bump published simpleredis, `MGet`, or operator Redis keys.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_cache_redis_in-tree-client`: `Client.New` SHALL store a distinct `*simpleredis.SimpleRedis` per write/read host; `nextReader` SHALL return those same pointers.

## Impact

- `pkg/cache/cache_test.go`
- `openspec/specs/core_cache_redis_in-tree-client/spec.md` (archive sync)
- Plugin public config unchanged. Not **BREAKING**.
