## Purpose

The plugin Redis cache uses this repository’s pooled SimpleRedis client in `pkg/simpleredis`, not the published `github.com/maxlerebourg/simpleredis` module.

## Requirements

### Requirement: In-tree package is the Redis client
The plugin SHALL import `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/simpleredis` for Redis GET/SET/DEL (and SHALL expose `MGet` on that package). Runtime SHALL NOT import `github.com/maxlerebourg/simpleredis`. `pkg/simpleredis` is this plugin’s Redis client (pooled connections, RESP arrays, `Init`/`Get`/`Set`/`Del`/`MGet`). It MUST NOT be required to match an outside simpleredis repository or pull request. `pkg/simpleredis` MUST NOT contain `LICENSE` or `SOURCE` pin files.

#### Scenario: Cache compiles against pkg/simpleredis
- **WHEN** a reviewer inspects `pkg/cache/cache.go` and `go.mod`
- **THEN** the cache imports the in-tree package and `go.mod` does not require `github.com/maxlerebourg/simpleredis`

#### Scenario: MGet is available without cache calling it
- **WHEN** a caller uses `pkg/simpleredis`
- **THEN** `MGet([]string) ([][]byte, error)` exists

#### Scenario: Package has no upstream pin files
- **WHEN** a reviewer inspects `pkg/simpleredis`
- **THEN** `LICENSE` and `SOURCE` are absent

### Requirement: Pooled client is not copied by value
After `Init`, each `SimpleRedis` used by the cache SHALL be referenced by pointer (`writer` and `readers`). The cache MUST NOT store `SimpleRedis` values in a slice after initialisation.

#### Scenario: nextReader returns a pooled pointer
- **WHEN** `redisCache` has one or more read hosts
- **THEN** `nextReader` returns `*simpleredis.SimpleRedis` that points at a reader (or the writer when there are no readers), not a copy of the struct

### Requirement: Client.New holds Redis readers by pointer
`Client.New` with Redis enabled SHALL allocate a distinct `*simpleredis.SimpleRedis` for the writer and for each `readHosts` entry, call `Init` on that pointer, and store those pointers on `redisCache`. It MUST NOT copy a `SimpleRedis` value into `readers` after `Init`. `nextReader` SHALL return the stored pointers (or the writer when `readHosts` is empty).

#### Scenario: New stores distinct reader pointers
- **WHEN** `Client.New` is called with Redis enabled and two read hosts
- **THEN** `redisCache` has a non-nil writer pointer, two non-nil reader pointers distinct from each other and from the writer, and `nextReader` returns those same reader pointers

### Requirement: Close stops new dials
After `Close`, `Get`/`MGet`/`Set`/`Del` SHALL return `redis:unreachable` and MUST NOT open a new TCP connection. In-flight commands on a borrowed socket MAY finish; `release` MUST close that socket instead of returning it to the idle list. `Close` SHALL remain safe to call more than once.

#### Scenario: Get after Close does not accept a second connection
- **WHEN** a test client has completed one `Get` (one accept) and then `Close`
- **THEN** a following `Get` returns `redis:unreachable` and the fake server's accept count stays 1

### Requirement: Handshake and idle behaviour are tested
`pkg/simpleredis` tests SHALL cover: AUTH sent once per new dial (not before every command); SELECT sent once per new dial when a database is set; I/O deadline maps to `redis:timeout`; an idle connection older than the idle timeout is closed on the next borrow and a new dial is used.

#### Scenario: AUTH is not repeated on a reused connection
- **WHEN** `Init` is given a password and two sequential `Get`s reuse one connection
- **THEN** the fake server records one AUTH and two GETs

#### Scenario: Silent peer hits the I/O deadline
- **WHEN** a listener accepts and never replies
- **THEN** `Get` returns `redis:timeout`
