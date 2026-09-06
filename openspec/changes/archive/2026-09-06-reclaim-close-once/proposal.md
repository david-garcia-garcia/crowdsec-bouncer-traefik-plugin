## Why

Grace dispose (`drop` → grace → `fire`) calls the slot `closeFn` from both `fire` and the `life` watcher started on first `Open`. That breaks the documented exactly-once Close contract, can race non-idempotent closers, and is masked by tests that only assert `closes >= 1`.

## What Changes

- `fire` cancels the incarnation `life` context and logs dispose but does not call `closeFn`; the first-Open watcher alone calls Close when `life` ends (same path as `ResetForTest`).
- Race-loser extra `create()` on a lost first-Open still calls `closeFn` immediately (orphan constructor, not slot dispose).
- Unit tests assert exactly one Close on grace dispose, including under concurrent fire vs watcher.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `std_go_reclaim_context-lease`: Close runs exactly once per incarnation on dispose; `fire` does not duplicate the watcher Close.

## Impact

- `pkg/reclaim/table.go` — remove synchronous `closeFn` from `fire`.
- `pkg/reclaim/table_test.go` — strict Close count on grace dispose.
