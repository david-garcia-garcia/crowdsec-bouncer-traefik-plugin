## MODIFIED Requirements

### Requirement: Table file depends only on the Go standard library
The process table implementation SHALL come from utilities `reclaim` (`github.com/david-garcia-garcia/traefik-middleware-utilities/reclaim` at the `go.mod` pin). This package SHALL keep only a local shim: `Default`, `ProcessGrace` (30 seconds), `Open` / `OpenWithHooks`, exact `Peek`, exported `State` (`Awake`, `Asleep`), and `ResetForTest` / `ResetForTestWith`. It MUST NOT keep a local `table.go` fork. Exact `Peek` SHALL be an ad-hoc method on the vendored utilities `reclaim/table.go`, re-exported from this shim (`Peek` on `Default()`). It MUST NOT export `PeekLivePrefix` or `View`. It MUST NOT take `OpenTyped` (that helper still takes `func() (any, Hooks, error)` and does not remove hooks-as-function-values). Callers in another package MUST import this shim, not utilities `reclaim` directly. The stored value MUST be `any`. The table MUST NOT be a generic `Table[T]` used as `otherpkg.Table[*T]`.

#### Scenario: Shim re-exports Open and exact Peek
- **WHEN** the local reclaim package is listed for exports
- **THEN** `Default`, `ProcessGrace`, `Open`, `OpenWithHooks`, `Peek`, `State`, `Awake`, `Asleep`, `ResetForTest`, and `ResetForTestWith` resolve
- **AND** `PeekLivePrefix` and `View` do not exist

## ADDED Requirements

### Requirement: Exact Peek does not bind
`Peek(key)` SHALL return `(value any, state State, ok bool)` without binding a holder. Exported `State` SHALL be `Awake` and `Asleep` only (`type State int`; `const (Awake State = iota; Asleep)`). `ok` SHALL be false when the key is missing, the slot is gone, or the slot is busy (create/Wake/Sleep/Close in flight). Peek MUST NOT wait on a busy slot, MUST NOT increment holders, MUST NOT call Wake, and MUST NOT stop grace. Busy MUST NOT be returned as a `State`. Callers that need a missing-or-same-name store SHALL Open only after a non-busy Peek miss or a Peek hit whose value they accept.

#### Scenario: Peek of an awake key does not add a holder
- **WHEN** a key is Open with one live context
- **AND** Peek runs for that key
- **THEN** `ok` is true and `state` is `Awake`
- **AND** cancelling that one context still Sleeps the slot (Peek did not bind)

#### Scenario: Peek of a sleeping key leaves grace running
- **WHEN** the last holder of a key is gone and the slot is sleeping
- **AND** Peek runs for that key before grace ends
- **THEN** `ok` is true and `state` is `Asleep`
- **AND** grace still expires and Close still runs if no Open reclaims

#### Scenario: Peek of a missing or busy key is ok false
- **WHEN** Peek runs for a key that is absent
- **THEN** `ok` is false
- **AND** Peek of a key whose slot is busy also returns `ok` false without waiting
