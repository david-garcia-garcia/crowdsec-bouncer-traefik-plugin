## MODIFIED Requirements

### Requirement: Table file depends only on the Go standard library
The process table implementation SHALL come from utilities `reclaim` (`github.com/david-garcia-garcia/traefik-middleware-utilities/reclaim` at the `go.mod` pin). This package SHALL keep only a local shim: `Default`, `ProcessGrace` (30 seconds), `Open` / `OpenWithHooks`, and `ResetForTest` / `ResetForTestWith`. It MUST NOT keep a local `table.go` fork. It MUST NOT export `Peek`, `PeekLivePrefix`, or `View`. It MUST NOT take `OpenTyped` (that helper still takes `func() (any, Hooks, error)` and does not remove hooks-as-function-values). Callers in another package MUST import this shim, not utilities `reclaim` directly. The stored value MUST be `any`. The table MUST NOT be a generic `Table[T]` used as `otherpkg.Table[*T]`.

#### Scenario: Shim re-exports Open without Peek
- **WHEN** the local reclaim package is listed for exports
- **THEN** `Default`, `ProcessGrace`, `Open`, `OpenWithHooks`, `ResetForTest`, and `ResetForTestWith` resolve
- **AND** `Peek`, `PeekLivePrefix`, and `View` do not exist

### Requirement: Open creates once and binds a context
`Open(ctx, key, logger, create, hooks)` SHALL create on first call for a key, bind `ctx` as a holder, and panic if `ctx` is nil. `Open` SHALL return an error if `logger` is nil. `create` SHALL take no arguments. Hooks SHALL be `reclaim.Hooks` stored at put (`Sleep` / `Wake` / `Close`). A later `Open` for the same key (live or in grace) SHALL return the stored value and MUST NOT run `create`. Callers in another package MUST pass Hooks as funcs: Yaegi v0.16 panics on asserting a foreign concrete type to closer/sleeper. The package MUST NOT export `*Wrapped` or `OpenWithGrace`.

#### Scenario: Two holders one incarnation
- **WHEN** `Open` creates a value for a key
- **AND** a second `Open` attaches another live context
- **THEN** both return the same value
- **AND** `create` ran once

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

## REMOVED Requirements

### Requirement: Peek reports holders and sleep without binding
**Reason**: After one cursor-plus-Redis Client key, `Open` of that key Wakes the sleeper. Peek existed to inspect unexported table `items` for warn-and-wire and sleeper retitle. Upstream utilities `reclaim` v1.0.3 has no Peek.
**Migration**: Tests that asserted via Peek use pointer equality on the `Open` return or `ResetForTest`. No replacement inspect API.

### Requirement: PeekLivePrefix reports a live slot under a key prefix
**Reason**: `PeekLivePrefix` warn-and-wired a different-hash joiner onto the first live slot. After Redis stays on the Client key, that would wire a different-Redis joiner onto the first live slot and break store isolation.
**Migration**: `Open` the cursor-plus-Redis key. Different Redis is a different key.
