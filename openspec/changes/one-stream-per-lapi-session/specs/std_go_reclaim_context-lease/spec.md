## Purpose

Defines a keyed reclaim table that stores one value per key as `any`, survives constructor-context cancel when the same key is opened again within grace, and cancels the incarnation when it is not. Callers type-assert. The table is not generic (Yaegi cannot instantiate `Table[T]` from another package).

## Requirements

### Requirement: Table file depends only on the Go standard library
The table source SHALL import only Go standard-library packages. It MUST store `any`. It MUST NOT be a generic `Table[T]` used as `otherpkg.Table[*T]`.

#### Scenario: Stdlib-only imports
- **WHEN** the table file is listed for imports
- **THEN** every import path is a Go standard-library package

### Requirement: Process table is a singleton
The package SHALL expose one process-wide table (`Default` / package `Open`). Independent keys MUST NOT share an incarnation. Callers SHALL type-assert the value `Open` returns.

#### Scenario: Two keys stay independent
- **WHEN** key A and key B are both opened
- **THEN** they store different values
- **AND** disposing A does not dispose B

### Requirement: Open creates once and binds a context
`Open(ctx, key, logger, create)` SHALL create on first call for a key, bind `ctx` as a holder, and panic if `ctx` is nil. `Open` SHALL return an error if `logger` is nil. `create` SHALL take no arguments. If the value has `Close()`, the table SHALL call it when the incarnation ends. A later `Open` for the same key (live or in grace) SHALL return the stored value and MUST NOT run `create`.

#### Scenario: Two holders one incarnation
- **WHEN** `Open` creates a value for a key
- **AND** a second `Open` attaches another live context
- **THEN** both return the same value
- **AND** `create` ran once

### Requirement: Cancel then open within grace does not dispose
When every bound context for a key is Done, the table SHALL wait grace before canceling the lifetime. An `Open` in that window MUST reclaim without `create`. Zero grace SHALL dispose as soon as the last holder is gone. Negative table grace SHALL become 10 seconds. When the stored value has `ReclaimGrace()`, that duration SHALL be the wait for that slot. Values without it SHALL use the table grace. The table-wide default MUST NOT be changed to special-case one stored type.

#### Scenario: Reclaim before grace
- **WHEN** all contexts for a key are Done
- **AND** a new `Open` for that key occurs before grace ends
- **THEN** the stored value is returned
- **AND** `create` does not run

#### Scenario: Value ReclaimGrace overrides table
- **WHEN** the stored value implements `ReclaimGrace` of 30 milliseconds
- **AND** the table grace is 1 second
- **AND** all contexts for that key are Done
- **THEN** the incarnation is disposed before the table grace elapses

### Requirement: Peek reports holders and sleep without binding
`Peek(key)` SHALL return the stored value, the live holder count, whether the slot is sleeping (grace armed), and whether the key exists. It MUST NOT add a holder and MUST NOT run `create`.

#### Scenario: Peek during sleep
- **WHEN** the last holder for a key is Done and grace has not elapsed
- **THEN** `Peek` reports the value, zero holders, and sleeping
- **AND** the incarnation is not disposed by `Peek`

### Requirement: Last holder Sleeps; Open during grace Wakes; grace Close()s
When every bound context for a key is Done, if the value has `Sleep()` the table SHALL call it, then wait grace before `Close()`. An `Open` in that window MUST Wake (if the value has `Wake()`) without `create`. Callers MUST NOT Close or delete a slot.

#### Scenario: Sleep then Wake on reclaim
- **WHEN** all contexts for a key are Done
- **AND** the value implements Sleep/Wake
- **AND** a new `Open` for that key occurs before grace ends
- **THEN** `Sleep` ran once
- **AND** `Wake` ran
- **AND** `create` does not run
- **AND** `Close` has not run

### Requirement: PeekLivePrefix reports a live slot under a key prefix
`PeekLivePrefix(prefix)` SHALL return one stored value whose key starts with prefix and whose holder count is greater than zero. It MUST NOT add a holder, MUST NOT run `create`, and MUST ignore sleeping slots. When several live keys match, the lexicographically smallest key SHALL be returned. An empty prefix MUST miss.

#### Scenario: PeekLivePrefix during mixed live and sleep
- **WHEN** one key under a prefix is sleeping and another is live
- **THEN** `PeekLivePrefix` returns the live key
- **AND** the sleeping incarnation is not disposed
