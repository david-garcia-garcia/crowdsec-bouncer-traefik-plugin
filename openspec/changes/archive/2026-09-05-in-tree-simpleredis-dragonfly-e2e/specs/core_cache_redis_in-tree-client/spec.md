## Purpose

The plugin Redis cache uses an in-tree copy of the pooled SimpleRedis client from simpleredis PR #8, not the published v1.0.12 module.

## Requirements

### Requirement: In-tree package is the Redis client
The plugin SHALL import `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/simpleredis` for Redis GET/SET/DEL (and SHALL expose `MGet` on that package). Runtime SHALL NOT import `github.com/maxlerebourg/simpleredis`. The in-tree sources SHALL match simpleredis PR #8 (`pool-redis-connections`: pooled connections, RESP arrays, `Init`/`Get`/`Set`/`Del`/`MGet`).

#### Scenario: Cache compiles against pkg/simpleredis
- **WHEN** a reviewer inspects `pkg/cache/cache.go` and `go.mod`
- **THEN** the cache imports the in-tree package and `go.mod` does not require `github.com/maxlerebourg/simpleredis`

#### Scenario: MGet is available without cache calling it
- **WHEN** a caller uses `pkg/simpleredis`
- **THEN** `MGet([]string) ([][]byte, error)` exists; `pkg/cache` still uses `Get`/`Set`/`Del` for one key per request

### Requirement: Pooled client is not copied by value
After `Init`, each `SimpleRedis` used by the cache SHALL be referenced by pointer (`writer` and `readers`). The cache MUST NOT store `SimpleRedis` values in a slice after initialisation.

#### Scenario: nextReader returns a pooled pointer
- **WHEN** `redisCache` has one or more read hosts
- **THEN** `nextReader` returns `*simpleredis.SimpleRedis` that points at a reader (or the writer when there are no readers), not a copy of the struct
