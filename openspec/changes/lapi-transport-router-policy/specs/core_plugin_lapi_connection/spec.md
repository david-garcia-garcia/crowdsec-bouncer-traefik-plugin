## ADDED Requirements

### Requirement: LAPI HTTP transport is hot-swappable on Client
The `lapi.Client` SHALL hold replaceable LAPI HTTP transport (TLS, timeout, and CAPI bearer token state used for LAPI requests) in an `atomic.Value` field, using the same pattern as in-process range membership (not a generic atomic pointer type from another package). Stream cursor and ticker scalars on `Client` SHALL remain write-once after construction. HTTP callers SHALL load the current transport value for each request.

#### Scenario: Transport load is lock-free
- **WHEN** stream mode runs `handleStreamTicker` without holding `Client.mu`
- **AND** another goroutine publishes a new transport via adoption
- **THEN** poll and lookup paths observe either the previous or the new transport atomically
- **AND** cursor health counters are not mutated on the adoption path

### Requirement: AdoptTransport after OpenStream
After a successful `OpenStream` (create, bind, wake, or live joiner wired to the owner key), the implementation SHALL compare transport-relevant configuration to the stored transport and, when different, build a new transport, store it in the atomic value, and close idle connections on the superseded HTTP client. Adoption SHALL NOT set stream startup or reset the CrowdSec stream cursor.

#### Scenario: Joiner rotates TLS on shared cursor
- **WHEN** a live stream joiner binds to an owner’s reclaim key and differs only on an LAPI TLS field
- **THEN** the shared `lapi.Client` adopts the joiner’s transport
- **AND** stream polling continues without forcing `startup=true` solely for that TLS change

### Requirement: LAPI connection INFO traceability
INFO-level connection lifecycle logs SHALL include the stream session key (or prefix) and a short `reason`. When transport is replaced, an INFO line SHALL name the configuration fields that changed. When a live joiner’s settings differ from the stored client, an INFO line SHALL list fields ignored (still in the settings hash, first-wins) and fields adopted (transport). Reclaim table debug lines (`reclaim_put`, `reclaim_reclaim`, `reclaim_dispose`) SHALL remain DEBUG.

#### Scenario: Default logger sees adoption not reclaim spam
- **WHEN** the plugin logger is at INFO
- **AND** transport is adopted on reload
- **THEN** an INFO line documents the adopted transport fields
- **AND** reclaim_put / reclaim_dispose messages are absent

### Requirement: LiveLookup accepts decision TTL parameter
Live decision lookup SHALL take the effective live cache TTL (from the calling bouncer’s `defaultDecisionSeconds`) as an argument. The `lapi.Client` MUST NOT store per-router default decision duration.

#### Scenario: Per-router live TTL
- **WHEN** two live middlewares share one `lapi.Client` and differ on `defaultDecisionSeconds`
- **THEN** each bouncer passes its own TTL into live lookup
- **AND** cached live entries use the TTL supplied by the bouncer that performed the lookup
