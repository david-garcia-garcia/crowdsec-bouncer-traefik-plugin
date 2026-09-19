## Purpose

The plugin Redis cache uses the vendored traefik-middleware-utilities SimpleRedis client, not `pkg/simpleredis` and not the published `github.com/maxlerebourg/simpleredis` module.

## Requirements

### Requirement: Vendored utilities client is the Redis client
The plugin SHALL import `github.com/david-garcia-garcia/traefik-middleware-utilities/simpleredis` for Redis GET/SET/DEL/MGET. Runtime SHALL NOT import `github.com/maxlerebourg/simpleredis` and MUST NOT keep `pkg/simpleredis`. `go.mod` SHALL require `github.com/david-garcia-garcia/traefik-middleware-utilities` at `v1.0.4` and that module SHALL be present under `vendor/`.

#### Scenario: Cache compiles against utilities SimpleRedis
- **WHEN** a reviewer inspects `pkg/cache/cache.go` and `go.mod`
- **THEN** the cache imports `github.com/david-garcia-garcia/traefik-middleware-utilities/simpleredis`
- **AND** `go.mod` requires that module at `v1.0.4`
- **AND** `go.mod` does not require `github.com/maxlerebourg/simpleredis`
- **AND** `pkg/simpleredis` is absent

#### Scenario: MGet is available on the client
- **WHEN** a caller uses the utilities SimpleRedis type
- **THEN** `MGet(ctx, []string) ([][]byte, error)` exists

### Requirement: Client is constructed with New and explicit timeouts
`Client.New` with Redis enabled SHALL call `simpleredis.New` with Host, Pass, Database, and this plugin’s dial 2s and command 1s (idle 30s, pool 8). It MUST NOT use `Init` or an empty struct. It MUST NOT rely on utilities zero-Config defaults for dial or command timeout.

#### Scenario: New stores distinct reader pointers
- **WHEN** `Client.New` is called with Redis enabled and two read hosts
- **THEN** `redisCache` has a non-nil writer pointer, two non-nil reader pointers distinct from each other and from the writer, and `nextReader` returns those same reader pointers

### Requirement: Pooled client is not copied by value
After `New`, each `SimpleRedis` used by the cache SHALL be referenced by pointer (`writer` and `readers`). The cache MUST NOT store `SimpleRedis` values in a slice after initialisation.

#### Scenario: nextReader returns a pooled pointer
- **WHEN** `redisCache` has one or more read hosts
- **THEN** `nextReader` returns `*simpleredis.SimpleRedis` that points at a reader (or the writer when there are no readers), not a copy of the struct

### Requirement: Commands pass a context
Cache Redis GET/MGET/SET/DEL SHALL pass a `context.Context`. When the cache API has no request context, that context SHALL be `context.Background()`.

#### Scenario: Get uses a context
- **WHEN** `redisCache.get` runs
- **THEN** it calls `Get` with a non-nil context

### Requirement: Close stops new dials
After `Close`, `Get`/`MGet`/`Set`/`Del` SHALL surface `cache:unreachable` and MUST NOT open a new TCP connection. `Close` SHALL remain safe to call more than once.

#### Scenario: Get after Close does not accept a second connection
- **WHEN** a test client has completed one `Get` (one accept) and then `Close`
- **THEN** a following `Get` returns `cache:unreachable` and the fake server's accept count stays 1

### Requirement: Miss and unreachable map through helpers or equal strings
Cache SHALL treat utilities miss as `cache:miss` and unreachable as `cache:unreachable`. Matching SHALL use `simpleredis.IsMiss` / `IsUnreachable` or the same `redis:miss` / `redis:unreachable` strings the module still exports.

#### Scenario: Miss becomes cache miss
- **WHEN** the client returns a miss
- **THEN** `Client.Get` returns `cache:miss`

### Requirement: Cache Client exposes a narrow lease acquire
`cache.Client` SHALL expose one acquire that talks to the writer plus prefix (Redis) or the memory mutex (local). Redis acquire SHALL call vendored SimpleRedis `Eval` (`EVALSHA` then `EVAL` on NOSCRIPT) with the prefixed key. Memory acquire SHALL lock around miss+Set. The method MUST NOT contain stream poller or LAPI query logic. The cache MUST NOT add a SetNX wrapper; SimpleRedis `Set` remains SET EX only. Acquire SHALL pass a `context.Context` (`context.Background()` when the cache API has no request context).

#### Scenario: Redis acquire uses Eval not Get-then-Set
- **WHEN** a Redis cache Client acquires an absent lease key
- **THEN** the writer sends `EVALSHA` or `EVAL`
- **AND** it does not send a GET followed by a SET for that acquire

#### Scenario: Memory acquire serializes miss and Set
- **WHEN** two goroutines acquire the same absent memory lease key
- **THEN** exactly one acquire wins
- **AND** the loser sees the key present

### Requirement: A key just written reads from the writer for a bounded window
`redisCache.set`, `redisCache.delete`, and `redisCache.acquire` SHALL record the key they write, and
`get` and `getMany` SHALL use the writer while **any** requested key is still inside that window.
Outside it they SHALL keep the round-robin over the read hosts. The key is recorded **before** the
write goes out, so a read taken while that write is still in flight also lands on the writer. A
client with no read hosts already reads the writer and SHALL do no pin bookkeeping.

The window SHALL be a constant in `pkg/cache`. It MUST NOT become a configuration key: the fix is a
correctness floor, not an operator preference. The guarantee is explicitly bounded — a replica
lagging longer than the window is a broken deployment, and no read routing inside the plugin can
hide that.

Reads MUST NOT all be sent to the writer. The read hosts exist to carry the per-request lookup load,
and removing that is a regression every request in every deployment pays to close a window that only
lagging-replica deployments have. The window MUST NOT be a single deadline covering every key
either: in `live` mode the cache is a per-request memo, writes never stop, and such a deadline would
never lapse, reaching writer-only reads by accident.

#### Scenario: A just-banned IP is not read back from a lagging replica
- **WHEN** a client with one read host that has not received the writer's data stores a remediation for an IP
- **AND** a `Get` or a `GetMany` for that IP follows immediately
- **THEN** the stored remediation comes back, not `cache:miss`

#### Scenario: A just-dropped decision is not read back as active
- **WHEN** both the writer and the read host hold a remediation for an IP, and the client deletes it
- **AND** a `Get` for that IP follows immediately
- **THEN** the result is `cache:miss`, not the remediation the read host still holds

#### Scenario: The read hosts carry reads again once the window elapses
- **WHEN** the window after a write has elapsed
- **THEN** a following `Get` for that key is served by a read host
- **AND** the writer serves no further `GET` for it

#### Scenario: Writing one key does not pin another
- **WHEN** one key is written and a different, untouched key is read
- **THEN** that read is served by a read host

### Requirement: The pinned-key set is capped and overflows toward the writer
The recorded-key set SHALL have a fixed cap. On reaching it the cache SHALL first drop entries whose
window has elapsed, and if it is still full SHALL pin **every** read for the window instead of
growing the set or dropping keys. A `startup=true` stream pull writes the whole decision list and is
exactly this case. Overflow MUST NOT fall back to the read hosts: the failure direction is the
writer.

#### Scenario: A burst past the cap does not grow the set
- **WHEN** more keys than the cap are written inside one window
- **THEN** the recorded-key set holds no more than the cap

#### Scenario: A burst past the cap keeps reads off the replicas
- **WHEN** more keys than the cap are written inside one window
- **AND** a key that was never written is then read
- **THEN** the writer serves that read and the read hosts serve none

### Requirement: A consistent read bypasses the read hosts and the window
`cache.Client` SHALL expose `GetConsistent`, which reads the writer whatever the window says. Memory
clients SHALL answer it exactly as `Get`, having no replicas to lag behind them.

It SHALL be used for a read-modify-write of a shared value, and for a read whose staleness keeps
changing the remediation served after the window has elapsed. Both Range-index reads qualify and
SHALL use it: `readRangeIndex`, because `ApplyRangeBatch` rewrites what it returns and a stale base
writes a truncated blob back for every instance, and `hydrateRangeMembership`, because
`storeRangeMembership` memoises the result as `lastRangeIndex` and serves it on every request until
the blob next changes. Both run once per update interval, so neither adds per-request cost.

The per-request lookup (`LookupCachedRemediation`) SHALL NOT use it. That path is what the read hosts
are for.

#### Scenario: A consistent read ignores a lagging read host
- **WHEN** the writer holds a value, the read host does not, and `GetConsistent` is called for it
- **THEN** the writer's value comes back and the read host serves no `GET`

#### Scenario: A range batch does not truncate the shared index
- **WHEN** the writer holds a Range index with an existing CIDR, the read host has not received it,
  and `ApplyRangeBatch` adds a second CIDR
- **THEN** the index on the writer holds both CIDRs

### Requirement: Unpinned Get uses nextReader only
When Redis read hosts are set, Get and GetMany for a key that is **not** inside the pin window SHALL call `nextReader` only. A miss or replica error MUST NOT be retried on the writer. When the reader list is empty, `nextReader` SHALL return the writer.

#### Scenario: Replica miss is not retried on the writer
- **WHEN** Redis has one or more read hosts, the key is not pinned, and Get on the selected reader returns miss
- **THEN** Get returns `cache:miss`
- **AND** the writer is not called for that Get

#### Scenario: Replica unreachable is not retried on the writer
- **WHEN** Redis has one or more read hosts, the key is not pinned, and Get on the selected reader is unreachable
- **THEN** Get returns `cache:unreachable`
- **AND** the writer is not called for that Get

### Requirement: Set and Delete are void
`cache.Client` Set and Delete SHALL return no error. Redis Set and Delete SHALL use the writer, log a Redis error, and return. The cache interface Set and Delete MUST NOT grow an error return. Stream and live callers MUST NOT fail closed on a write miss.

#### Scenario: Redis Set error is logged and discarded
- **WHEN** Redis Set on the writer fails
- **THEN** the error is logged
- **AND** `Client.Set` returns without an error value

### Requirement: Redis SET EX uses the duration as given
When Redis Set runs, it SHALL send `SET EX` with the duration integer as given. The cache MUST NOT omit `EX` or clamp the duration. Which durations reach Redis Set is owned by `core_cache_client_write-lifetime`: a non-positive `Client.Set` duration is a no-op and MUST NOT reach the writer. Stream write TTL is owned by `core_cache_client_decision-store` (`int64` of CrowdSec seconds, no clamp).

#### Scenario: A positive Redis Set sends EX as given
- **WHEN** Redis `Client.Set` is called with a positive duration
- **THEN** the writer sends `SET` with `EX` equal to that duration
- **AND** `EX` is not omitted

