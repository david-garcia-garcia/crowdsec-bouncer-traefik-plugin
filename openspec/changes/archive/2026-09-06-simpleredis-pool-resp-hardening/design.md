## Context

`SimpleRedis` pools TCP connections for the plugin Redis cache. Traefik request goroutines share each pool via `pkg/cache`. Current pool caps idle slice only; active dials are uncapped. `borrow()` unlocks before `dial()`, allowing post-`Close()` connections.

## Goals / Non-Goals

**Goals:**
- Hard stop on new dials after `Close()`.
- Bound total live connections (idle + checked out) to 8.
- Bound RESP allocations from peer headers.
- Do not pool session-fatal error sockets.
- Test coverage for the above.

**Non-Goals:**
- Blocking wait when at connection cap (fail-fast instead).
- Automatic redial on LOADING/READONLY.
- Cross-package cache changes.

## Decisions

- **`maxOpenConns = maxIdleConns` (8):** Reserve a slot under `mu` before dial; decrement on dial failure or socket close.
- **Close vs dial:** Re-check `closed` under `mu` after dial; discard conn if closed during dial.
- **RESP caps:** `maxBulkBytes = 16 MiB`, `maxArrayCount = 4096`; over-limit returns `redis:issue?` with non-reusable conn.
- **Session-fatal errors:** `do()` returns `reusable=false` for NOAUTH, WRONGPASS, NOPERM, LOADING, READONLY, and AUTH handshake errors.

## Risks / Trade-offs

- Fail-fast at connection cap may surface `redis:unreachable` under extreme Traefik concurrency → acceptable vs unbounded sockets.
- 16 MiB bulk cap exceeds any legitimate cache value in this plugin.
