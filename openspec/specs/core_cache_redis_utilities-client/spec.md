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

### Requirement: Redis Int uses existing byte Set and Get
`Set` of a `uint32` and `GetInt` on a Redis cache Client SHALL encode the `uint32` as decimal ASCII through existing SimpleRedis `Set`/`Get` `[]byte`. Callers MUST treat that encoding as opaque. The cache MUST NOT add an Int helper on SimpleRedis. A GetInt that cannot parse that encoding (including a leftover remediation string) SHALL return `CacheMiss`. Stream and alone Redis writers MAY keep leftover strings via `Set`. Commands SHALL pass a `context.Context` (`context.Background()` when the cache API has no request context).

#### Scenario: Redis GetInt misses a leftover string
- **WHEN** a Redis cache Client Sets a leftover remediation string on an Ip key
- **THEN** GetInt of that key returns `CacheMiss`
- **AND** Get of that key returns the leftover string

#### Scenario: Redis Set of a word round-trips
- **WHEN** a Redis cache Client Sets key `k` to `uint32` `116`
- **THEN** GetInt of `k` returns `116`

### Requirement: Get uses nextReader only
When Redis read hosts are set, Get and GetMany SHALL call `nextReader` only. A miss or replica error MUST NOT be retried on the writer. The cache MUST NOT keep a local set of recently written keys. When the reader list is empty, `nextReader` SHALL return the writer.

#### Scenario: Replica miss is not retried on the writer
- **WHEN** Redis has one or more read hosts and Get on the selected reader returns miss
- **THEN** Get returns `cache:miss`
- **AND** the writer is not called for that Get

#### Scenario: Replica unreachable is not retried on the writer
- **WHEN** Redis has one or more read hosts and Get on the selected reader is unreachable
- **THEN** Get returns `cache:unreachable`
- **AND** the writer is not called for that Get

### Requirement: Set and Delete are void
`cache.Client` Set and Delete SHALL return no error. Redis Set and Delete SHALL use the writer, log a Redis error, and return. The cache interface Set and Delete MUST NOT grow an error return. Stream and live callers MUST NOT fail closed on a write miss.

#### Scenario: Redis Set error is logged and discarded
- **WHEN** Redis Set on the writer fails
- **THEN** the error is logged
- **AND** `Client.Set` returns without an error value

### Requirement: Redis SET EX uses the duration as given
Redis Set SHALL send `SET EX` with the duration integer as given, including `0`. The cache MUST NOT omit `EX`, clamp a non-positive duration, or skip the Redis write because duration is `0`. Memory `Heap.Set` SHALL no-op when `ttl` is `0` (does not store). Redis and memory MUST NOT be aligned.

#### Scenario: Redis Set with duration 0 sends EX 0
- **WHEN** Redis `Client.Set` is called with duration `0`
- **THEN** the writer sends `SET` with `EX 0`
- **AND** the write is not skipped

#### Scenario: Memory Set with ttl 0 does not store
- **WHEN** a memory `Client.Set` is called with duration `0`
- **THEN** the key is absent on a following Get
