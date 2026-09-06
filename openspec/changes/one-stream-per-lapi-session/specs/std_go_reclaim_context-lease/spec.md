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
When every bound context for a key is Done, the table SHALL wait grace before canceling the lifetime. An `Open` in that window MUST reclaim without `create`. Zero grace SHALL dispose as soon as the last holder is gone. Negative grace SHALL become 10 seconds.

#### Scenario: Reclaim before grace
- **WHEN** all contexts for a key are Done
- **AND** a new `Open` for that key occurs before grace ends
- **THEN** the stored value is returned
- **AND** `create` does not run

### Requirement: Peek reports holders and sleep without binding
`Peek(key)` SHALL return the stored value, the live holder count, whether the slot is sleeping (grace armed), and whether the key exists. It MUST NOT add a holder and MUST NOT run `create`.

#### Scenario: Peek during sleep
- **WHEN** the last holder for a key is Done and grace has not elapsed
- **THEN** `Peek` reports the value, zero holders, and sleeping
- **AND** the incarnation is not disposed by `Peek`

### Requirement: Last holder Sleeps; Open during grace Wakes; grace Close()s
When every bound context for a key is Done, if the value has `Sleep()` the table SHALL call it, then wait grace before `Close()`. An `Open` in that window MUST Wake (if the value has `Wake()`) without `create`. Callers MUST NOT Close or delete a slot; `ReplaceSleeping` MAY dispose a sleeper inside the table then `Open`.

#### Scenario: Sleep then Wake on reclaim
- **WHEN** all contexts for a key are Done
- **AND** the value implements Sleep/Wake
- **AND** a new `Open` for that key occurs before grace ends
- **THEN** `Sleep` ran once
- **AND** `Wake` ran
- **AND** `create` does not run
- **AND** `Close` has not run

### Requirement: ReplaceSleeping disposes a sleeper then Open
`ReplaceSleeping(ctx, key, logger, create)` SHALL `Close()` a zero-holder incarnation inside the table, then behave as `Open`. If live holders remain, it MUST NOT dispose (same as `Open` bind).

#### Scenario: ReplaceSleeping during sleep
- **WHEN** a key is sleeping with zero holders
- **AND** `ReplaceSleeping` is called
- **THEN** the stored value’s `Close` runs before grace would have elapsed
- **AND** `create` runs for the new incarnation
