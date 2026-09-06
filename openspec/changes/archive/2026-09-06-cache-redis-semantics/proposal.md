## Why

Redis and in-memory cache backends diverge on TTL-zero writes, hide Set/Delete failures, and route reads only through round-robin replicas — so bans, stream leases, and captcha grace can miss immediately after a successful-looking write. CI covers CRUD only on `localCache`.

## What Changes

- `duration <= 0` is a documented no-op on memory and Redis (nothing stored).
- `Client.Set` and `Client.Delete` return `error`; Redis propagates write failures.
- After a successful Redis `Set`, this instance reads that key from the writer until `Delete` (read-your-writes).
- Redis-backend CRUD parity tests with fake Redis (TTL zero, errors, prefix, GetMany, read-after-write lag).
- Call sites updated only to compile (`_ =` acceptable); fail-closed upstream wiring is follow-up.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_cache_redis_in-tree-client`: TTL-zero contract, observable Set/Delete errors, read-your-writes routing, Redis CRUD tests.

## Impact

- `pkg/cache/cache.go`, `pkg/cache/cache_test.go`, `pkg/cache/redis_cache_test.go`
- Minimal call-site signature fixes in `pkg/lapi`, `pkg/decisionscope`, `pkg/captcha`
