## Purpose

Defines a keyed reclaim table that stores one value per key as `any`, survives constructor-context cancel when the same key is opened again within grace, and cancels the incarnation when it is not. Callers type-assert. The table is not generic (Yaegi cannot instantiate `Table[T]` from another package).

## Requirements

### Requirement: Table file depends only on the Go standard library
The process table implementation SHALL come from utilities `reclaim` (`github.com/david-garcia-garcia/traefik-middleware-utilities/reclaim` at the `go.mod` pin). This package SHALL keep only a local shim: `Default`, `ProcessGrace` (30 seconds), `Open` / `OpenWithHooks`, and `ResetForTest` / `ResetForTestWith`. It MUST NOT keep a local `table.go` fork. It MUST NOT export `Peek`, `PeekLivePrefix`, or `View`. It MUST NOT take `OpenTyped` (that helper still takes `func() (any, Hooks, error)` and does not remove hooks-as-function-values). Callers in another package MUST import this shim, not utilities `reclaim` directly. The stored value MUST be `any`. The table MUST NOT be a generic `Table[T]` used as `otherpkg.Table[*T]`.

#### Scenario: Shim re-exports Open without Peek
- **WHEN** the local reclaim package is listed for exports
- **THEN** `Default`, `ProcessGrace`, `Open`, `OpenWithHooks`, `ResetForTest`, and `ResetForTestWith` resolve
- **AND** `Peek`, `PeekLivePrefix`, and `View` do not exist

### Requirement: Process table is a singleton
The package SHALL expose one process-wide table (`Default` / package `Open`). That table SHALL be constructed with `ProcessGrace` (30 seconds). Independent keys MUST NOT share an incarnation. Callers SHALL type-assert the value `Open` returns.

#### Scenario: Two keys stay independent
- **WHEN** key A and key B are both opened
- **THEN** they store different values
- **AND** disposing A does not dispose B

### Requirement: Open creates once and binds a context
`Open(ctx, key, logger, create, hooks)` SHALL create on first call for a key, bind `ctx` as a holder, and panic if `ctx` is nil. `Open` SHALL return an error if `logger` is nil. `create` SHALL take no arguments. Hooks SHALL be `reclaim.Hooks` stored at put (`Sleep` / `Wake` / `Close`). A later `Open` for the same key (live or in grace) SHALL return the stored value and MUST NOT run `create`. Callers in another package MUST pass Hooks as funcs: Yaegi v0.16 panics on asserting a foreign concrete type to closer/sleeper. The package MUST NOT export `*Wrapped` or `OpenWithGrace`.

#### Scenario: Two holders one incarnation
- **WHEN** `Open` creates a value for a key
- **AND** a second `Open` attaches another live context
- **THEN** both return the same value
- **AND** `create` ran once

### Requirement: Cancel then open within grace does not dispose
When every bound context for a key is Done, the table SHALL wait the table grace before canceling the lifetime. An `Open` in that window MUST reclaim without `create`. Zero grace SHALL dispose as soon as the last holder is gone. Negative table grace SHALL become 10 seconds. Values opened with `Open` SHALL use the table grace. There is no per-put grace override.

#### Scenario: Reclaim before grace
- **WHEN** all contexts for a key are Done
- **AND** a new `Open` for that key occurs before grace ends
- **THEN** the stored value is returned
- **AND** `create` does not run

### Requirement: Last holder Sleeps; Open during grace Wakes; grace Close()s
When every bound context for a key is Done, if `hooks.Sleep` is set the table SHALL call it, then wait grace before `hooks.Close`. An `Open` in that window MUST Wake (`hooks.Wake`) without `create`. Callers MUST NOT Close or delete a slot.

#### Scenario: Sleep then Wake on reclaim
- **WHEN** all contexts for a key are Done
- **AND** the put stored Sleep/Wake hooks
- **AND** a new `Open` for that key occurs before grace ends
- **THEN** `Sleep` ran once
- **AND** `Wake` ran
- **AND** `create` does not run
- **AND** `Close` has not run

#### Scenario: Foreign type uses Hooks
- **WHEN** `create` in another package returns a value and the Open call passes Sleep/Wake/Close funcs
- **THEN** the table calls those funcs on last holder / reclaim / dispose
- **AND** `Open` returns that value
