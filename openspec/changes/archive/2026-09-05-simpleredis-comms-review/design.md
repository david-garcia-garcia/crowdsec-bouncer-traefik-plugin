## Context

Dest `master` already has `pkg/simpleredis` (PR #8 pool + RESP + `MGet` + `Close`) and `CrowdsecConnection.Close` → `cache.Client.Close`. `borrow` still dials after `closed`. Official go-redis is documented in `knowledge/research/ext_redis_go-redis` (Go 1.24, unsafe/syscall). `useUnsafe` is documented in `knowledge/research/ext_traefik_plugins_useunsafe`.

FindSpecHost: fold into `core_cache_redis_in-tree-client` (small adjustment to an existing leaf).

## Goals / Non-Goals

**Goals:**
- Close without redial.
- Tests for AUTH, SELECT, timeout, idle eviction, no-redial-after-Close.

**Non-Goals:**
- go-redis, `useUnsafe`, pipelining, cache `GetMany`, Dragonfly e2e, rename `do`/`clean`.

## Decisions

1. **Fail closed.** After Close, `borrow` checks `closed` under the mutex and returns `errUnreachable` before `dial`.
2. **Keep the fake Redis.** Extend it to count AUTH/SELECT; add a silent listener for timeout.
3. **SOURCE note.** One line that this tree also stops dial-after-Close (still based on f8801cc).

## Risks / Trade-offs

- [Callers that Get after Close and expected a new pool] → None in this repo; cache Close is dispose-only.
- [Timeout test ~1s] → Accept; `ioTimeout` is 1s.

## Migration Plan

No operator config change. Rollback is revert.
