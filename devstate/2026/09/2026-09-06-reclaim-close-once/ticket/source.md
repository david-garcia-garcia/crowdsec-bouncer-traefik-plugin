# Grace dispose calls Close twice on the same incarnation

## reclaim-close-once

### Problem
On the normal grace-dispose path, `fire` and the `life` watcher both invoke `closeFn`. `Close` can run twice, sometimes concurrently. LAPI/AppSec clients happen to tolerate it; the table contract is exactly-once dispose. Tests only assert `closes >= 1`.

### Desired
Exactly-once `closeFn` on grace dispose (and still on drop). Test that Close runs once, including concurrent fire vs watcher.

### Out of scope
Open/drop/fire races already tested. Call-site Sleep/Wake.

## close-twice-on-dispose

### Problem
When a slot is disposed through the normal grace path (`drop` → `fire`), the table invokes the stored `closeFn` from `fire` and again from the `life` watcher goroutine started on first `Open`. That breaks the documented "call Close when this incarnation ends" contract, races non-idempotent closers, and is masked by tests that only assert `closes >= 1`.

### Evidence
- pkg/reclaim/table.go:236-241 — first `Open` for a key starts `go func() { waitCtx(life); closeFn() }`.
- pkg/reclaim/table.go:321-327 — `fire` cancels `life` then calls the same `closeFn` before the watcher finishes.
- pkg/reclaim/table.go:158 — comment: table calls Close "when this incarnation ends" (once).
- pkg/reclaim/table.go:432-463 — `ResetForTest` cancels `life` only; dispose relies on the watcher goroutine (single Close path).
- pkg/reclaim/table_test.go:1100 — `TestTable_GraceClosesAfterSleep` waits for `paused.closes.Load() >= 1`, not exactly one.
- pkg/lapi/client.go:203-209 — `Client.Close` is idempotent today (`closed` guard).
- pkg/appsec/client.go:77-82 — `Client.Close` has no guard but only closes idle HTTP connections (harmless duplicate today).

### Desired
Pick one dispose owner for `closeFn`: either `fire` (and any other explicit teardown) calls it and the `life` goroutine only observes cancellation without closing, or `fire`/`ResetForTest` only cancel `life` and the watcher alone calls `closeFn`. Add a unit test with a counting closer that fails unless `Close` runs exactly once per incarnation on the grace-dispose path.

### Out of scope
Reclaim races on concurrent `Open`/`drop`/`fire` (covered by existing concurrent tests). LAPI `OpenStream` / AppSec `Open` key choice. FNV key collision risk. `context.Background()` holders. Per-Open grace ignored on slot reuse. Deadlock via Sleep/Wake under `t.mu`.
