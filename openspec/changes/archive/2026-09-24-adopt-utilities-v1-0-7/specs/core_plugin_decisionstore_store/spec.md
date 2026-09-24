## MODIFIED Requirements

### Requirement: Redis engine uses utilities SimpleRedis
The Redis engine SHALL import `github.com/david-garcia-garcia/traefik-middleware-utilities/simpleredis` for GET/SET/DEL/MGET/MSetEX. Runtime SHALL NOT import `github.com/maxlerebourg/simpleredis` and MUST NOT keep `pkg/simpleredis` or `pkg/cache`. `go.mod` SHALL require `github.com/david-garcia-garcia/traefik-middleware-utilities` at `v1.0.7`. Construction SHALL call `simpleredis.New` with Host, Pass, Database, dial 2s and command 1s (idle 30s, pool 8). Writer and readers SHALL be pointers. Commands SHALL pass `context.Background()` when the store API has no request context. After Close, Get/MGET/SET/DEL/MSetEX SHALL surface `store:unreachable` and MUST NOT open a new TCP connection. Close SHALL remain safe to call more than once.

#### Scenario: Redis compiles against utilities SimpleRedis
- **WHEN** a reviewer inspects `pkg/decisionstore/redis.go` and `go.mod`
- **THEN** the Redis engine imports `github.com/david-garcia-garcia/traefik-middleware-utilities/simpleredis`
- **AND** `go.mod` requires that module at `v1.0.7`
- **AND** `pkg/cache` is not the Redis client
