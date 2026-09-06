# Spec

1. [wrong] `openspec/changes/lapi-client-correctness/specs/core_plugin_lapi_failure-action/spec.md` — Scenario "Active IP remediation when scope query fails" — WHEN IP query yields active ban AND scope fails, THEN LiveLookup returns error AND bouncer still remediates from IP ban kind; `mergeLiveScope` returns `"", 0, headerErr` and `handleNoStreamCache` returns `"", scopeErr`, so `kind` is empty and bouncer applies failure action instead of IP ban
   → On scope query failure, preserve `chosen` when it is active remediation; return `(chosen, scopeErr)` from `handleNoStreamCache`
   Status: done
   Argument: mergeLiveScope preserves chosen on scope error; handleNoStreamCache returns chosen when active remediation.

2. [missing] `openspec/changes/lapi-client-correctness/specs/core_plugin_lapi_failure-action/spec.md` — Scenario "Active IP remediation when scope query fails" — no httptest covers IP ban + scope LAPI failure returning error with active remediation value
   → Add test: IP query returns ban, scope query 500, assert `LiveLookup` returns error and value is active remediation
   Status: done
   Argument: TestLiveLookupScopeErrorPreservesActiveIPBan added.
