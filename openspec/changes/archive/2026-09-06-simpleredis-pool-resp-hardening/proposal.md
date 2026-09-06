## Why

The in-tree `pkg/simpleredis` client has concurrency and shutdown defects: `Close()` does not atomically stop new dials, concurrent callers can open unbounded TCP connections, hostile RESP bulk/array headers can force huge allocations, and session-fatal `-ERR` replies are returned to the idle pool.

## What Changes

- Serialize close vs dial so post-`Close()` commands cannot open new sockets.
- Cap total live connections per `SimpleRedis` at `maxOpenConns` (8, matching idle cap); fail-fast when at cap.
- Cap RESP bulk length (16 MiB) and array count (4096) before allocation.
- Treat session-fatal Redis errors (NOAUTH, WRONGPASS, LOADING, READONLY, etc.) as non-reusable; close socket.
- Add fake-server tests for concurrency, shutdown, RESP limits, dial failures, and error replies.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_cache_redis_in-tree-client`: pool hardening, RESP limits, session-fatal error handling, and expanded test coverage.

## Impact

- `pkg/simpleredis/simpleredis.go`
- `pkg/simpleredis/simpleredis_test.go`
- Plugin public config unchanged. Not **BREAKING**.
