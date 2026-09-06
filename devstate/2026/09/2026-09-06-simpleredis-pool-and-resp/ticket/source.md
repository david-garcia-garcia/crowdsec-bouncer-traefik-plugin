# Close/dial race, unbounded conns and RESP allocs, pooling after session-fatal -ERR

## Problem
In-tree Redis client:

1. `borrow()` checks `closed` then dials without the lock — commands can succeed after Close.
2. `maxIdleConns` caps idle only; concurrent callers can open unbounded TCP connections.
3. `$<n>` / `*<count>` from the peer drive unbounded `make()` (DoS from a hostile Redis).
4. `-ERR` replies (e.g. -NOAUTH) mark the conn reusable; AUTH only runs in `dial()`, so bad sockets stay in the pool.
5. Dial AUTH/SELECT failure, post-Close Set/Del/MGet, malformed RESP, `Get` → `redis:issue?` untested.

## Sibling: close-dial-toctou-race
`SimpleRedis.Close()` documents that further Get/Set/Del/MGet return redis:unreachable and do not dial. `borrow()` checks `closed` before calling `dial()`, but the check and the dial are not atomic. During plugin shutdown, this race can briefly open sockets to Redis and even return cache hits after the client was closed.

Desired: Hold `closed` protection through the dial decision, or re-check `closed` immediately after a successful `dial()` and before running the user command. Add concurrent Close/dial test.

Out of scope: In-flight commands that already hold a pooled connection before Close() — explicitly allowed.

## Sibling: unbounded-active-connections
`maxIdleConns` (8) limits idle slice only, not open sockets. When every idle connection is checked out, each additional concurrent `exec()` dials a fresh TCP connection. Under Traefik traffic spike many goroutines can share one `*SimpleRedis` reader.

Desired: Cap in-flight connections per `SimpleRedis` (block or fail fast). Test with more goroutines than `maxIdleConns`.

Out of scope: Cross-host fan-out, server-side connection limits.

## Sibling: resp-unbounded-allocation
`readBulk` and array branch of `readReply` trust length/count from server with no upper bound. Hostile Redis can send huge `$` or `*` headers forcing large allocations.

Desired: Define maximum bulk size and array length; reject over-limit replies before allocating. Unit tests with fake servers.

Out of scope: Operator-trusted Redis on private network. Client-side key/value sizes bounded elsewhere.

## Sibling: do-reusable-on-redis-error-replies
`do()` marks every cleanly parsed reply as reusable, including `-ERR` lines. Session-fatal errors (NOAUTH, WRONGPASS, LOADING, READONLY) return socket to idle pool; AUTH only runs in `dial()`.

Desired: Treat session-fatal Redis errors as non-reusable; close connection. Tests for empty password + AUTH-required server.

Out of scope: Wrong password during `dial()` — already closes connection.

## Sibling: dial-and-close-coverage-gaps
Dial handshake failures and post-Close operations beyond Get are untested. Missing: AUTH/SELECT failure in dial(), Set/Del/MGet after Close(), Get redis:issue?, malformed RESP.

Desired: Focused fake-server tests for each gap.

Out of scope: `-race` coverage, E2E Dragonfly tests.

## Desired (summary)
Serialize close vs dial so Close stops new commands. Bound active connections. Cap RESP allocations. Do not pool session-fatal error sockets. Tests for those paths and listed coverage gaps.

## Out of scope
Happy-path reuse, idle eviction, MGET nil slots already tested.
