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
After `Close`, `Get`/`MGet`/`Set`/`Del` SHALL return `redis:unreachable` and MUST NOT open a new TCP connection. In-flight commands on a borrowed socket MAY finish; `release` MUST close that socket instead of returning it to the idle list. `Close` SHALL remain safe to call more than once. The check for `closed` and any new dial SHALL be serialized so a concurrent `Close()` during dial cannot leave a live pooled connection.

#### Scenario: Get after Close does not accept a second connection
- **WHEN** a test client has completed one `Get` (one accept) and then `Close`
- **THEN** a following `Get` returns `redis:unreachable` and the fake server's accept count stays 1

#### Scenario: Close during blocked dial does not add a connection
- **WHEN** `Close` runs while another goroutine is blocked in dial
- **THEN** no new accept is recorded after `Close` completes and subsequent `Get` returns `redis:unreachable`

### Requirement: Connection count is bounded
Each `SimpleRedis` SHALL limit total live TCP connections (idle plus checked out) to `maxOpenConns` (8). When at cap, new borrows that would dial SHALL return `redis:unreachable` without opening another socket.

#### Scenario: Peak connections stay within cap
- **WHEN** more concurrent goroutines than `maxOpenConns` each call `Get` on one client
- **THEN** the fake server's peak accept count is at most `maxOpenConns`

### Requirement: RESP allocations are bounded
The RESP parser SHALL reject bulk lengths above 16 MiB and array counts above 4096 before allocating. Over-limit replies SHALL return `redis:issue?` and MUST NOT reuse the connection.

#### Scenario: Oversized bulk is rejected
- **WHEN** the fake server replies with a bulk header larger than the cap
- **THEN** `Get` returns `redis:issue?` and the connection is not repooled

#### Scenario: Oversized array is rejected
- **WHEN** the fake server replies with an array count above the cap
- **THEN** `MGet` returns `redis:issue?` and the connection is not repooled

### Requirement: Session-fatal errors do not repool
When Redis returns `-ERR` for NOAUTH, WRONGPASS, NOPERM, LOADING, READONLY, or AUTH handshake failure, the client SHALL close the socket and MUST NOT return it to the idle pool.

#### Scenario: NOAUTH after handshake does not repool
- **WHEN** a reused connection receives `-ERR NOAUTH`
- **THEN** the client returns `redis:noauth` and the next command dials a fresh connection

### Requirement: Handshake and idle behaviour are tested
`pkg/simpleredis` tests SHALL cover: AUTH sent once per new dial (not before every command); SELECT sent once per new dial when a database is set; I/O deadline maps to `redis:timeout`; an idle connection older than the idle timeout is closed on the next borrow and a new dial is used; dial-time AUTH/SELECT failure; Set/Del/MGet after Close; Get unexpected reply shape.

#### Scenario: AUTH is not repeated on a reused connection
- **WHEN** `Init` is given a password and two sequential `Get`s reuse one connection
- **THEN** the fake server records one AUTH and two GETs

#### Scenario: Silent peer hits the I/O deadline
- **WHEN** a listener accepts and never replies
- **THEN** `Get` returns `redis:timeout`

#### Scenario: Set after Close returns unreachable
- **WHEN** `Close` has been called on the client
- **THEN** `Set` returns `redis:unreachable` without a new accept
