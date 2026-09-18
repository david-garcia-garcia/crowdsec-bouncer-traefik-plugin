# Dead

1. [hard] Test-only new symbol — `pkg/cache/stored.go:61` — `LeftoverOrigin` has no callers outside tests after drop resolve moved to `RemediationOrigin` / `ParsePackedOriginID`
   → Delete it; assert leftover suffix via `RemediationOrigin` on `IndexForm()`
   Status: done
   Argument: f7bd466 deleted `LeftoverOrigin`; leftover tests assert `RemediationOrigin` on `IndexForm()`.
