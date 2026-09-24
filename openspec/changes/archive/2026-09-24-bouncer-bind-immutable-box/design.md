## Context

See proposal.md Why. Today `storeBinding` assigns `boxed.Value = value` when `dest.Load()` already holds `*reclaim.Box`; first publish only does `dest.Store(&reclaim.Box{Value: value})`. `ReceiveLAPI` / `ReceiveAppSec` / `ReceiveCaptcha` feed that helper from Watch notices. `ServeHTTP` reads via `reclaim.Unbox` (Load pointer, then plain `Value` field). Explore Decisions are accepted: always Store a new Box; keep Unbox/Watch; optional `watchInto` companion; Findings 2/3 out of scope.

FindSpecHost (propose, before folder write):

```
verdicts:
  - deltaId: late-bind-immutable-box
    fold|new|skip: fold
    spec-id: core_plugin_middleware_bouncer
    confidence: high
    candidates:
      - core_plugin_middleware_bouncer
      - core_plugin_middleware_instance-slots
      - std_go_reclaim_context-lease
```

Small adjustment to the existing late-bind requirement (publish shape). Neighbors stay as-is. No new leaf.

## Goals / Non-Goals

**Goals:**

- One publish path: every bind update Stores a new `*reclaim.Box`.
- Yaegi type freeze stays `*reclaim.Box`.
- Nil client / mode-from-published-client behavior unchanged.
- Test helper `watchInto` matches that publish shape.
- Race-detector coverage where cgo exists.

**Non-Goals:**

- Findings 2 and 3.
- Changing `Unbox` / `Watch` / `Published` API.
- Mutex around `Box.Value`, `atomic.Pointer[T]`, or reclaim API reshape.
- Unrelated bouncer policy.
- Rewriting usage docs in apply (Gotchas already on disk; verify at devdocsimpact).
- Touching `zzz_bind_test.go` bare `*Client` Store helpers.

## Decisions

| Topic | Choice | Rationale |
|-------|--------|-----------|
| Seam | `storeBinding` only always `dest.Store(&reclaim.Box{Value: value})` | Requirement names that shape; three Receive* stay thin feeders. |
| API | Keep Unbox/Watch/Published | Out of scope; bouncer owns the Store. |
| Yaegi | Concrete type remains `*reclaim.Box` | Live Box comment + vendor reclaim; `atomic.Pointer` forbidden. |
| Catalog | Fold `core_plugin_middleware_bouncer` MODIFIED late-bind | Explore: no new capability leaf. |
| Companion | Fix `watchInto` Store-new-Box | Explore deviation; stops tests teaching the race. |
| Proof | Focused concurrent Unbox vs Store + `go test -race` when cgo present | Explore host lacked gcc; implement measures on a race-capable host. |

**Alternatives rejected:** mutex on `Box.Value`; `atomic.Pointer[T]`; change Unbox to lock/copy; Watch Stores Box into subscriber atomics itself.

## Risks / Trade-offs

- **Extra Box allocations per publish** → Accepted. Publish is rare vs ServeHTTP; correctness wins.
- **Race detector unavailable on some hosts** → Implement still lands the Store fix; run `-race` where cgo exists; document skip otherwise.
- **Stale Box pointers briefly linger until Unbox sees the new Store** → Desired; readers see a consistent snapshot, never a torn `any`.

## Migration Plan

- Deploy. No config rewrite. Rollback is revert of the PR.

## Open Questions

None. Explore rows stay as explore wrote them.
