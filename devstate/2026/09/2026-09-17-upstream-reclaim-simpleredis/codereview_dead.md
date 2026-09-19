# Dead

1. [hard] Test-only new symbol — `pkg/reclaim/opentyped.go:16` — `OpenTyped` wraps `OpenWithHooks` and type-asserts to `T`; grep `OpenTyped` across `*.go` hits only this definition (no production or test callers; `pkg/lapi` and `pkg/appsec` still assert after `reclaim.OpenWithHooks`)
   → Delete `opentyped.go`, or call `OpenTyped` from the LAPI/AppSec open paths and drop duplicated asserts
   Status: done
   Argument: deleted pkg/reclaim/opentyped.go.

2. [hard] Dead branch or constant — `pkg/lapi/client.go:18-19` — `ReclaimGraceDuration` is no longer read in production after `OpenWithGrace(..., ReclaimGraceDuration, ...)` was removed from `pkg/lapi/session.go`; grep `ReclaimGraceDuration` in non-test production `.go` is zero (only `plugin_test.go` and `session_test.go` remain)
   → Remove the constant; tests that need 30s should use `reclaim.ProcessGrace`
   Status: done
   Argument: tests use reclaim.ProcessGrace; lapi const removed.

3. [hard] Dead branch or constant — `pkg/appsec/client.go:13-14` — `ReclaimGraceDuration` has no callers after AppSec `Open` switched to `reclaim.OpenWithHooks`; grep `ReclaimGraceDuration` / `appsec.ReclaimGraceDuration` across `*.go` hits only this definition
   → Delete the unused constant
   Status: done
   Argument: deleted unused appsec.ReclaimGraceDuration.
