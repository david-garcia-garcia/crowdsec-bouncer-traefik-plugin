## 1. Configuration and wiring

- [x] 1.1 Remove `redisCacheEnabled`, host/read hosts, password, database, and `redisCacheUnreachableBlock` from `pkg/configuration` (JSON tags, defaults, validation)
- [x] 1.2 Simplify LAPI client construction: drop Redis args to `cache.Client.New`; remove Redis fields from `streamSettings` / session warn-and-wire diff
- [x] 1.3 Remove bouncer `RedisUnreachableBlock()` path and related tests

## 2. Cache package

- [x] 2.1 Delete `redisCache` implementation and Redis branch in `pkg/cache/cache.go`
- [x] 2.2 Adjust `Client.New` signature and all call sites/tests to memory-only
- [x] 2.3 Run `go mod tidy` and `go mod vendor`; confirm no product import of `simpleredis` unless another package still needs utilities

## 3. LAPI stream lease

- [x] 3.1 Keep `handleStreamCache` lease on in-memory Client; update comments on `SessionHex` / `CachePrefix` as memory-only
- [x] 3.2 Update unit tests in `pkg/lapi` and `pkg/cache` off Redis fixtures

## 4. Examples and operator docs

- [x] 4.1 Remove `examples/redis-cache/` and Redis keys from other samples
- [x] 4.2 Remove README Redis cache section; note breaking change and per-replica LAPI polling

## 5. E2e

- [x] 5.1 Delete mock e2e Redis scenario and RESP stand-in usage tied to plugin cache
- [x] 5.2 Remove Dragonfly service and Redis-backed Pester routes from real stack compose/tests

## 6. Knowledge / devdocs

- [x] 6.1 Update `knowledge/devdocs/core_cache_client.md` and index; remove or fold `core_cache_redis.md` with LAPI cursor rationale

## 7. Verify

- [x] 7.1 `go test ./pkg/...`
- [x] 7.2 Run applicable e2e subset after Redis scenario removal
