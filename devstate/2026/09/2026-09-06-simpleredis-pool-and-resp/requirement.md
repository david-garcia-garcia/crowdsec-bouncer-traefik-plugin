# Requirement
IssueKey: 2026-09-06-simpleredis-pool-and-resp

## Problem
The in-tree `pkg/simpleredis` Redis client has concurrency, shutdown, pooling, and RESP-parser defects: commands can dial and succeed after `Close()`, concurrent callers can open unbounded TCP connections, hostile bulk/array headers can force huge allocations, session-fatal `-ERR` replies are returned to the idle pool, and several dial/close/error paths lack tests.

## Current (code)
- `pkg/simpleredis/simpleredis.go:64-78` — `Close()` sets `closed`, drains idle; comment promises no dial after close except in-flight finish.
- `pkg/simpleredis/simpleredis.go:152-188` — `borrow()` reads `closed` under mutex, unlocks, then calls `dial()` with no lock; TOCTOU between unlock and dial.
- `pkg/simpleredis/simpleredis.go:28` — `maxIdleConns = 8` caps idle slice only.
- `pkg/simpleredis/simpleredis.go:186-187` — when idle empty, every waiter dials; no active-connection cap.
- `pkg/simpleredis/simpleredis.go:315-330` — `readBulk` allocates `make([]byte, length+2)` with no max length.
- `pkg/simpleredis/simpleredis.go:289-308` — array replies allocate `make([][]byte, count)` with no cap.
- `pkg/simpleredis/simpleredis.go:234-245` — `do()` sets `reusable=true` whenever `readReply` is clean, including `-ERR`.
- `pkg/simpleredis/simpleredis.go:219-229` — `AUTH`/`SELECT` only in `dial()`; pooled conn skips re-auth.
- `pkg/simpleredis/simpleredis.go:344-351` — `replyError` maps NOAUTH/WRONGPASS to `redis:noauth` but conn still pooled via `do()`.
- `pkg/cache/cache.go:96-103` — many request goroutines can share one `*SimpleRedis` via `nextReader()` round-robin.
- `pkg/simpleredis/simpleredis_test.go:357-384` — `TestCloseDrainsIdleAndDoesNotRepool` only sequential Close then Get; no concurrent Close during dial.
- `pkg/simpleredis/simpleredis_test.go:191-214` — `TestConcurrentCommandsStayWithinPool` uses exactly eight goroutines; does not prove ninth stays capped.
- `pkg/simpleredis/simpleredis_test.go` — no over-limit `$`/`*` header tests; no dial-time AUTH/SELECT failure tests; Set/Del/MGet after Close untested; Get `redis:issue?` untested.

## Desired
- Serialize close vs dial (hold protection through dial or re-check `closed` after dial) so `Close()` stops new commands; test concurrent Close during blocked dial.
- Bound active TCP connections per `SimpleRedis` (match idle cap or explicit `maxOpenConns`); test peak count with goroutines > `maxIdleConns`.
- Cap RESP bulk length and array count before allocation; reject over-limit with non-reusable error; fake-server tests.
- Treat session-fatal `-ERR` (NOAUTH, WRONGPASS, LOADING, READONLY) as non-reusable; close socket; tests for repool behavior.
- Add focused fake-server tests: dial AUTH/SELECT failure, Set/Del/MGet after Close, Get unexpected reply shape, malformed RESP.

## Affected
- `pkg/simpleredis/simpleredis.go` — `borrow`, `release`, `dial`, `do`, `readReply`, `readBulk`
- `pkg/simpleredis/simpleredis_test.go` — new concurrency, shutdown, RESP limit, error-reply, dial-failure tests

## Out of scope
- Happy-path reuse, idle eviction, MGET nil slots (already tested).
- In-flight commands holding a pooled conn before `Close()` (explicitly allowed by Close comment).
- Cross-host fan-out (each read host has its own pool).
- Operator-trusted Redis with no adversary model for RESP limits.
- Wrong password during `dial()` handshake (already closes conn).
- `-race` coverage, E2E Dragonfly tests under `tests/e2e/`.

## Unknowns
- Exact max bulk size and array count for cache values (decision blobs, range indexes) — explore must pick limits aligned with plugin cache usage.
- Active-connection policy when cap reached: block vs fail-fast — ticket allows either; explore decides.
- Whether `-LOADING`/`-READONLY` warrant one redial vs fail-fast — ticket says optionally redial once.

## Tensions
- Close comment allows in-flight commands to finish; concurrent dial-after-Close fix must not break that contract.
- RESP caps must fit legitimate cache payloads; ticket says sizes bounded elsewhere but no numeric ceiling cited in code.
- `TestConcurrentCommandsStayWithinPool` name implies pool limit; current test only uses eight goroutines matching idle cap — behavior vs test name mismatch until fixed.
