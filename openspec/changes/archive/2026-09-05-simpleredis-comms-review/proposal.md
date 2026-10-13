## Why

On `master`, `pkg/simpleredis` already pools connections, but `Get` after `Close` still dials a new TCP socket. That wastes sockets after reclaim disposes a CrowdsecConnection. Official `go-redis` is not usable in this Yaegi plugin (Go 1.24, unsafe/syscall). Communication-layer tests also skip AUTH, SELECT, I/O timeout, and idle-timeout eviction.

## What Changes

- After `Close`, `borrow` returns `redis:unreachable` and does not dial.
- Unit tests: no redial after Close; AUTH once per new dial; SELECT once per new dial; I/O timeout; idle-timeout eviction.
- Do not take `github.com/redis/go-redis`. Do not set `.traefik.yml` `useUnsafe`.
- Do not call `MGet` from `pkg/cache`. Do not change operator Redis keys.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_cache_redis_in-tree-client`: Close stops new dials; AUTH/SELECT/timeout/idle-timeout and no-redial-after-Close are covered by `pkg/simpleredis` tests.

## Impact

- `pkg/simpleredis/simpleredis.go`, `pkg/simpleredis/simpleredis_test.go`, `pkg/simpleredis/SOURCE`
- Not **BREAKING**. Public `Init`/`Get`/`Set`/`Del`/`MGet`/`Close` stay. Close after dispose is stricter (no silent redial).
