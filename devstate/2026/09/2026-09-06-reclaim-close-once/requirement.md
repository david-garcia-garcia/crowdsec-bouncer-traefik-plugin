# Requirement
IssueKey: 2026-09-06-reclaim-close-once

## Problem
Grace dispose (`drop` → grace → `fire`) invokes the slot `closeFn` from both `fire` and the `life` watcher started on first `Open`, so `Close` can run twice and concurrently. The table documents exactly-once dispose; current LAPI/AppSec closers tolerate repeats; tests only require `closes >= 1`.

## Current (code)
- `pkg/reclaim/table.go:158` — Open doc: table calls Close when the incarnation ends (once).
- `pkg/reclaim/table.go:236-241` — first Open starts `life` watcher that calls `closeFn` after `waitCtx(life)`.
- `pkg/reclaim/table.go:321-327` — `fire` cancels `life` and synchronously calls the same `closeFn`.
- `pkg/reclaim/table.go:432-463` — `ResetForTest` cancels `life` only; dispose relies on watcher (single Close path).
- `pkg/reclaim/table_test.go:1100` — `TestTable_GraceClosesAfterSleep` asserts `closes >= 1`, not exactly one.
- `pkg/lapi/client.go:203-209` — `Client.Close` idempotent via `closed` guard.
- `pkg/appsec/client.go:77-82` — `Client.Close` closes idle HTTP only; duplicate call harmless today.

## Desired
Single owner for `closeFn` on grace dispose: either `fire`/explicit teardown calls it and the `life` watcher only observes cancellation, or `fire`/`ResetForTest` only cancel `life` and the watcher alone closes. Add a unit test with a counting closer that fails unless `Close` runs exactly once per incarnation on the grace-dispose path (including concurrent fire vs watcher).

## Affected
- `pkg/reclaim/table.go` — dispose path (`fire`, first-Open watcher, possibly `ResetForTest` alignment).
- `pkg/reclaim/table_test.go` — grace-dispose Close assertion.

## Out of scope
Concurrent Open/drop/fire races (existing tests). Call-site Sleep/Wake behavior. LAPI/AppSec Open key choice. FNV collision. Background holders never released. Per-Open grace ignored on slot reuse. Sleep/Wake deadlock under `t.mu`.

## Unknowns
Which single-owner design (`fire` vs watcher) fits all teardown paths (`fire`, zero-grace drop, `ResetForTest`, race-loser extra create) without regressions.

## Tensions
Ticket asks exactly-once on grace dispose while `ResetForTest` today uses watcher-only Close; aligning both may require touching test teardown, not only `fire`. Weak test masks double Close until a strict assertion is added.
