## MODIFIED Requirements

### Requirement: Table file depends only on the Go standard library
The process table implementation SHALL come from utilities `reclaim` (`github.com/david-garcia-garcia/traefik-middleware-utilities/reclaim` at the `go.mod` pin). This package SHALL keep only a local shim: `Default`, `ProcessGrace` (30 seconds), `Open` / `OpenWithHooks`, exact `Peek`, exported `State` (`Awake`, `Asleep`), and `ResetForTest` / `ResetForTestWith`. It MUST NOT keep a local `table.go` fork. Exact `Peek` SHALL be the published utilities table method at the `go.mod` pin, re-exported from this shim (`Peek` on `Default()`). It MUST NOT export `PeekLivePrefix` or `View`. It MUST NOT take `OpenTyped` (that helper still takes `func() (any, Hooks, error)` and does not remove hooks-as-function-values). Callers in another package MUST import this shim, not utilities `reclaim` directly. The stored value MUST be `any`. The table MUST NOT be a generic `Table[T]` used as `otherpkg.Table[*T]`.

#### Scenario: Shim re-exports Open and exact Peek
- **WHEN** the local reclaim package is listed for exports
- **THEN** `Default`, `ProcessGrace`, `Open`, `OpenWithHooks`, `Peek`, `State`, `Awake`, `Asleep`, `ResetForTest`, and `ResetForTestWith` resolve
- **AND** `PeekLivePrefix` and `View` do not exist
