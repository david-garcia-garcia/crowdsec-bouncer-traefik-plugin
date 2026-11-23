# `admission.Gate.BackingOff` has no production caller

IssueKey: 2026-11-23-waf-unknown-length-body
Size: large
Action: note

## Why this follow-up
This change removed the unreadable-body drop paths in `pkg/appsec/query.go` and `pkg/modsecurity/inspect.go`, which were the only production callers of `admission.Gate.BackingOff()`. The method now has callers only in tests (`pkg/admission/zzz_admission_test.go`, `pkg/appsec/zzz_gate_test.go`). It is exported surface with no production use.

## Why it was not taken
The admission gate and its BackOffAction belong to the parallel run `2026-11-23-backoff-action-per-leg`, whose branch still calls `BackingOff()` on the paths this change deletes and may need it for a per-leg BackOffAction. This ticket must not change gate behaviour (requirement, out of scope 9). Deleting the method here would conflict with that run.

## Risks
Once both branches land, `BackingOff` may stay as dead exported code, or the merge of `2026-11-23-backoff-action-per-leg` may reintroduce a body-based gate skip that this change removed on purpose.

## Context
Current: `pkg/admission/admission.go` `func (g *Gate) BackingOff() bool`; test-only callers.
Proposed: when `2026-11-23-backoff-action-per-leg` lands, either use it for the per-leg BackOffAction or delete it and its tests.
