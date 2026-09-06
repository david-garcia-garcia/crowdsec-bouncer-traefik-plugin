## Context

The reclaim table starts a goroutine on first put that waits on the incarnation `life` context and calls `closeFn` when it ends. `fire` (grace elapsed or zero-grace drop) also called the same `closeFn` after canceling `life`, so Close could run twice and concurrently. `ResetForTest` already relied on watcher-only Close.

## Goals / Non-Goals

**Goals:**
- Exactly one `closeFn` call per incarnation dispose path.
- Align `fire` with `ResetForTest` (cancel only; watcher closes).
- Tests fail on double Close.

**Non-Goals:**
- Open/drop/fire concurrency races (already tested).
- Call-site Sleep/Wake behavior.
- Making LAPI/AppSec Close idempotent (separate concern).

## Decisions

1. **Watcher owns Close.** `fire` deletes the slot, cancels `life`, logs dispose; the existing watcher goroutine is the sole Close caller for normal teardown.
2. **Race-loser keeps Close.** When a racing `create()` loses to another Open, its `closeFn` runs immediately — that value never entered the table.
3. **Test with panicking counter.** A test closer panics if `Close` runs more than once to catch regressions under concurrency.

## Risks / Trade-offs

- Close timing shifts from synchronous in `fire` to asynchronous in the watcher — callers already treat Close as incarnation-end cleanup, not tied to `fire` returning.
