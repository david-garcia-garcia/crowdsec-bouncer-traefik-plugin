## ADDED Requirements

### Requirement: DecisionStore owns stream Ip and header remediation store
A DecisionStore SHALL own one stream store for stream and alone Ip and header-scope slots, selected once when the store Opens. A Redis-backed store SHALL delegate Put and Delete to the owned `cache.Client` with stream write TTL semantics (CrowdSec duration seconds, no live-cache substitution). A memory-backed store SHALL hold one `atomic.Value` whose payload is `map[string]liveSlot` where each `liveSlot` carries a packed remediation `word` and CrowdSec `expiresAt` in epoch seconds. Memory Put and Delete during a stream apply tick SHALL mutate a tick-local clone only; memory SHALL publish that map with a single `Store` after each successful stream apply tick via BeginTick and PublishTick. Memory MUST NOT Set stream or alone Ip or header request keys on the TTL heap. Redis BeginTick and PublishTick SHALL be no-ops. Stream store state SHALL live on the reclaim DecisionStore value (same Traefik constructor context as `lapi.OpenStream` / `OpenLive`), not on `lapi.Client` and not in package globals.

#### Scenario: Memory stream IP is not on the TTL heap
- **WHEN** stream/alone memory stores an Ip ban for a client address
- **THEN** the TTL heap does not hold that Ip key
- **AND** the stream store map holds a packed word for that key after PublishTick

#### Scenario: Redis stream IP still uses cache Client
- **WHEN** stream/alone Redis stores an Ip ban
- **THEN** Get or GetInt of that Ip key on the owned cache Client returns the remediation
- **AND** BeginTick and PublishTick do not change Redis keys

#### Scenario: Stream store shares reclaim with cache
- **WHEN** two Clients Open the same DecisionStore reclaim key
- **THEN** a stream Ip ban written by the first is visible to the second through the shared stream store

### Requirement: Memory stream tick publishes once per apply
On memory backends, when one stream payload is applied, the store SHALL BeginTick once, apply every deleted and new Ip/header decision through the tick clone, sweep expired slots by `expiresAt`, then PublishTick once. It MUST NOT publish after each individual Put or Delete.

#### Scenario: Single publish after full payload
- **WHEN** one stream payload adds two Ip bans and deletes one header scope
- **THEN** observers see at most one new map generation for that apply
- **AND** all three mutations appear together after PublishTick

## MODIFIED Requirements

### Requirement: DecisionStore owns the origin intern table
A DecisionStore SHALL own a `pkg/intern.Table` (copy-on-write `byName` string→`uint16` and `byID` id→string; lock-free `Name`) and a thin `OriginName` lookup. CrowdSec `Pack`/`Unpack` SHALL live in `pkg/decisionscope`. The pack word SHALL be `uint32(kind[0]) | uint32(id)<<8`. The table MUST NOT be a package variable. Two DecisionStores with different reclaim keys MUST NOT share the table. Intern MUST stay off `lapi.Client` except thin forwards tests need. When intern would overflow `uint16`, the store SHALL log at Warn level and SHALL store a kind-only packed word with origin id `0` on the memory stream path. Stream and alone memory Ip and header writes SHALL `Pack` into the stream store (not `cache.Client.Set`). Stream and alone Redis Ip and header writes SHALL `Pack` then `Set` on the owned cache Client. Live/none and range-index SHALL keep leftover strings via `Set`. Memory stream lookup MUST NOT use `GetMany` to recover overflow origin strings. Client address SHALL reuse `pkg/ip.GetRemoteIP`. CrowdSec cursor identity SHALL reuse `SessionHex`.

#### Scenario: Memory stream IP write packs the intern id
- **WHEN** stream/alone memory stores an Ip ban whose origin is `crowdsec`
- **THEN** the stream store holds a word whose low byte is `t` and whose origin id names `crowdsec` via `OriginName`

#### Scenario: Distinct stores do not share intern ids
- **WHEN** two DecisionStores have different reclaim keys and both intern `crowdsec`
- **THEN** each store’s `OriginName` answers only from its own table

#### Scenario: Overflow stores kind-only on memory stream path
- **WHEN** intern would assign an id past `uint16` max and memory stream stores that Ip slot
- **THEN** the stream store word carries the ban or captcha kind with origin id `0`
- **AND** lookup returns the kind without an origin name
- **AND** a Warn is logged

#### Scenario: Redis overflow keeps leftover strings
- **WHEN** intern would overflow on a Redis-backed stream Ip write
- **THEN** that slot is stored with `Set` as a leftover string on the cache Client
- **AND** GetInt of that slot is `ErrMiss`
