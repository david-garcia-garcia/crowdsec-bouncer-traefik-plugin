## MODIFIED Requirements

### Requirement: Open creates once and binds a context
`Open(ctx, key, logger, create)` SHALL create on first call for a key, bind `ctx` as a holder, and panic if `ctx` is nil. `Open` SHALL return an error if `logger` is nil. `create` SHALL take no arguments. If the value has `Close()`, or `create` returned `*Wrapped` with `Close` set, the table SHALL call that Close exactly once when the incarnation ends. A later `Open` for the same key (live or in grace) SHALL return the stored value (the inner value when `*Wrapped`) and MUST NOT run `create`. `create` in another package MUST return `*Wrapped` for Sleep/Wake/Close: Yaegi v0.16 panics on asserting a foreign concrete type to those interfaces.

#### Scenario: Grace dispose Close runs once
- **WHEN** all contexts for a key are Done
- **AND** grace elapses
- **THEN** the table calls Close exactly once for that incarnation
- **AND** concurrent fire and life-watcher teardown does not call Close twice

### Requirement: Last holder Sleeps; Open during grace Wakes; grace Close()s
When every bound context for a key is Done, if the value has `Sleep()` or `*Wrapped.Sleep` is set the table SHALL call it, then wait grace before `Close()`. An `Open` in that window MUST Wake (if the value has `Wake()` or `*Wrapped.Wake` is set) without `create`. Callers MUST NOT Close or delete a slot. Dispose (`fire` or zero-grace drop) SHALL cancel the incarnation lifetime; the first-Open life watcher alone SHALL invoke Close when that lifetime ends.

#### Scenario: Sleep then Wake on reclaim
- **WHEN** all contexts for a key are Done
- **AND** the value implements Sleep/Wake or `create` returned `*Wrapped` with those funcs
- **AND** a new `Open` for that key occurs before grace ends
- **THEN** `Sleep` ran once
- **AND** `Wake` ran
- **AND** `create` does not run
- **AND** `Close` has not run
