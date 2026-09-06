## MODIFIED Requirements

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
