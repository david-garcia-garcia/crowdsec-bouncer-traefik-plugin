## Why

Closed #38 asked for Redis read-your-writes, duration<=0 aligned no-op, and Set/Delete errors for fail-closed stream/captcha. The owner rejected all three. Dest has no spec sentence that locks replica-lag reads, void Set, EX-as-given, or the stream vs live TTL split, so a later defect hunt can re-open them.

## What Changes

- Fold current cache-client and store-write tradeoffs into existing cache specs. No Redis/memory runtime change. No signature change. No test that asserts a new runtime policy.
- Short comments at `nextReader` / `get` / `set` and stream `int64(duration.Seconds())` only if a one-liner earns its keep.
- README `RedisCacheReadHosts`: no lag/stale-read sentence (explore: the knob already names replica-only reads and outage fail-closed).
- Devdocs gotchas: not this change (ticket defers to later `devdocsimpact`).

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_cache_redis_utilities-client`: lock replica-only `nextReader` Gets (no writer retry), void Set/Delete that log Redis errors, and SET EX as given including `0`. Memory `Heap.Set` no-ops when `ttl==0`; MUST NOT align the two backends.
- `core_cache_client_decision-store`: lock stream write TTL as `int64(duration.Seconds())` with no clamp, and live/none write TTL as `liveCacheTTL` (substitute `defaultDecisionSeconds` when `durationSecond<=0`).

## Impact

- `openspec/specs/core_cache_redis_utilities-client/spec.md`
- `openspec/specs/core_cache_client_decision-store/spec.md`
- `pkg/cache/cache.go` (comments only: `nextReader`, `get`, `set`)
- `pkg/lapi/client_stream.go` (comment only at `int64(duration.Seconds())`, if kept)
- Official Redis SET EX / replica lag: `knowledge/research/ext_redis_commands_set-ex-zero/`, `knowledge/research/ext_redis_replication_replica-lag/`
- No **BREAKING** public JSON/YAML keys
- Out of scope: writer-on-recent-key, Set/Delete error return, stream TTL clamp, aligning memory with Redis, changing `liveCacheTTL`, captcha cache grace, SimpleRedis fork, backendbackoff, HTTP timeouts, captcha JSON, module rename, closed #38 / `2026-09-18-cache-ttl-guard-and-read-your-writes`
