# Standards

1. [hard] Leave a trail — `bouncer_logging_test.go:63` — `newTestLogFile` is a new helper with no succinct job comment while sibling helpers in the same file document their contract (e.g. `createAndExecuteBouncerRequest` at `:81`)
   → Add one line stating it creates an isolated temp log path and resets reclaim with zero grace so file-logging tests do not inherit process-table grace from `t.TempDir` / prior cases
   Status: done
   Argument: job comment on newTestLogFile.

2. [judgement] Symmetry and consistency — `pkg/appsec/session.go:66-71` vs `pkg/lapi/session.go:216-223,271-274` — this diff retargets both packages to `OpenWithHooks` but LAPI centralizes `clientHooks` and `clientFromStored` while AppSec still inlines `reclaim.Hooks{...}` and the post-Open type assert in `Open`
   → Extract `clientHooks` and `clientFromStored` in `pkg/appsec` to match the LAPI reclaim path and Yaegi comment
   Status: skipped
   Argument: judgement; AppSec Open is one call site, extract is extra shape.

3. [judgement] Name for the scope — `pkg/reclaim/opentyped.go:16` — parameter `t *Table` reads like `*testing.T` in a test-heavy repo; the body only calls `t.OpenWithHooks`
   → Rename the parameter to `table` (or `tab`) so the reclaim table role is obvious at the signature
   Status: skipped
   Argument: OpenTyped deleted with Dead 1.
