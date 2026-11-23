# Test coverage

1. [hard] Edge case untested — `pkg/lapi/client_decisions.go:162` — `liveQueryHealthy` counts any error that is not a `statusError` (refused connection, timeout) as a gate failure; every trip test uses 503, so treating a transport error as healthy would stay green
   Fix: Add a live lookup subtest against a closed LAPI that trips the gate after 5 refused connections
   Status: done
   Argument: Added subtest "refused connection trips" to `TestLiveLookup_statusClassification`; verified it fails when `liveQueryHealthy` treats a non-status error as healthy.
2. [hard] Assertion does not prove the job — `pkg/lapi/client_decisions.go:221` — the scope WARN is suppressed on `ErrGateSkip`, but the only absence assertion (`TestLiveLookup_probeRecoversAndLogsOnce`) passes nil scopes, so the guard is never reached and its revert stays green
   Fix: Capture WARN in `TestLiveLookup_skippedScopeAfterAnsweredIP` (clean IP, skipped scope) and assert no `handleNoStreamCache:scopeQuery` line
   Status: done
   Argument: `TestLiveLookup_skippedScopeAfterAnsweredIP` now captures WARN and asserts no `handleNoStreamCache:scopeQuery`; verified it fails when the `ErrGateSkip` guard is removed.
3. [judgement] Happy path only — `pkg/bouncer/bouncer_serve_lapi.go:86` — the shared-gate / per-router-action split is proven for AppSec only; no test binds two routers to one tripped live LAPI client with different `bouncerLapiBackOffAction`
   Fix: Add `TestServeHTTP_twoRoutersOnOneLapiGate`: default router bans `ban:lapi-backoff`, passthrough router reaches next, LAPI not called
   Status: done
   Argument: Added `TestServeHTTP_twoRoutersOnOneLapiGate` in `pkg/bouncer/zzz_backoff_action_test.go`: one tripped live client, default router 403 `ban:lapi-backoff`, passthrough router reaches next, no LAPI call.
