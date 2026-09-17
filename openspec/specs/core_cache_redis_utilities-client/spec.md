## Purpose

The plugin Redis cache uses the vendored traefik-middleware-utilities SimpleRedis client, not `pkg/simpleredis` and not the published `github.com/maxlerebourg/simpleredis` module.

## Requirements

### Requirement: Vendored utilities client is the Redis client
The plugin SHALL import `github.com/david-garcia-garcia/traefik-middleware-utilities/simpleredis` for Redis GET/SET/DEL/MGET. Runtime SHALL NOT import `github.com/maxlerebourg/simpleredis` and MUST NOT keep `pkg/simpleredis`. `go.mod` SHALL require `github.com/david-garcia-garcia/traefik-middleware-utilities` at `v1.0.3` and that module SHALL be present under `vendor/`.

#### Scenario: Cache compiles against utilities SimpleRedis
- **WHEN** a reviewer inspects `pkg/cache/cache.go` and `go.mod`
- **THEN** the cache imports `github.com/david-garcia-garcia/traefik-middleware-utilities/simpleredis`
- **AND** `go.mod` requires that module at `v1.0.3`
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
