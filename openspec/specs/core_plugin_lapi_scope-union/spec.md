## Purpose

How a shared LAPI Client builds stream `scopes=` and the stream store filter from the union of live routers’ normalized header-scope maps, without mutating write-once `lapiScopeHeaders`.

## Requirements

### Requirement: Live routers union header scopes into stream query
Only the middleware that Opens the stream Client SHALL register `lapiScopeHeaders` on that Client. Bouncing subscribers MUST NOT register. Stream `scopes=` and the store filter still snapshot the opener's map (write-once plus that Open's ctx).

#### Scenario: Subscriber does not add scopes
- **WHEN** the opener published a stream Client with no `lapiScopeHeaders`
- **AND** a bouncing subscriber has `lapiScopeHeaders` Country
- **THEN** stream `scopes=` does not include Country from that subscriber

### Requirement: Growing the union does not send startup=true
When a later live router registers a header scope after the CrowdSec cursor has advanced, the Client MUST NOT send `startup=true` for that registration. LAPI `scopes=` is a filter of `id_gt`; a newly added scope misses decisions already past the cursor until a later incarnation `startup=true`.

#### Scenario: Late Country join misses prior Country bans
- **WHEN** a stream Client has already polled with `startup=false` after a Country ban’s id
- **AND** a later live router registers `Country`
- **THEN** the next stream query includes `country` and uses `startup=false`
- **AND** that already-passed Country ban is not backfilled by this registration

### Requirement: Shrinking the union does not sweep cache keys
When a registration is dropped, the Client MUST NOT sweep header-scope cache keys. Stale Country/AS keys expire with TTL or die with the store incarnation.

#### Scenario: Unregister leaves an existing Country key
- **WHEN** the store holds a Country ban key and the last `Country` registration is dropped
- **THEN** that cache key is not deleted by unregister
