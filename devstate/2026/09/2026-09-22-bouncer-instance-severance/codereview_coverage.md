# Test coverage

1. [hard] Edge case untested — `pkg/lapi/session.go:59` — stream `SessionHex` special-cases `CanonicalStreamScopes(crowdsecLapiStreamScopes)`; `pkg/lapi/zzz_scopeunion_test.go` only asserts the poll query string; no test would fail if that field were dropped from the hash
   → Assert a stream scope-list change forks `SessionHex` and the store (order-independent; omitted and empty hash the same; live/none leave the field empty)
   Status: skipped
   Argument: ticket job proven by 23/23 instance-severance + green CI; extra asserts deferred.
2. [hard] Assertion does not prove the job — `pkg/lapi/client.go:215` / `pkg/lapi/client.go:222` — Close Clears the slot, Sleep does not; `tests/e2e/real/instance_severance.Tests.ps1` N2 accepts `/sev-n2-admin` 403, 429, or 503, so an immediate unbind stays green
   → Assert the old subscriber stays 403 until grace `instance closed`, then 503 (no `unbound` before Close)
   Status: skipped
   Argument: ticket job proven by 23/23 instance-severance + green CI; extra asserts deferred.
3. [judgement] Happy path only — `pkg/bouncer/bouncer.go:255` — `ServeHTTP` reads mode from the loaded LAPI client; `(none)`
   → Assert a Publish that swaps stream for live changes the next request’s mode branch
   Status: skipped
   Argument: ticket job proven by 23/23 instance-severance + green CI; extra asserts deferred.
4. [judgement] Happy path only — `pkg/instance/tables.go:308` — bind-time `crowdsec bouncer stream scopes missing` WARN; `(none)`
   → Assert one WARN when `decisionScopeHeaders` names a scope the opener list does not cover
   Status: skipped
   Argument: ticket job proven by 23/23 instance-severance + green CI; extra asserts deferred.
