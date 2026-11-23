# Issues

- [ ] note large  `knowledge/debt/2026-11-23-appsec-call-ignores-inbound-cancel.md`
  Why: the AppSec listener request does not carry the inbound context, so a client that leaves keeps the call open until `appsecHttpTimeoutSeconds` (pre-existing; found by the 180 s `Test_appsecQuery_hopCancelDoesNotTripGate`).
- [ ] note large  `knowledge/debt/2026-11-23-admission-gate-backingoff-unused.md`
  Why: removing the unreadable-body drop paths left `admission.Gate.BackingOff()` with no production caller; the gate belongs to the parallel run `2026-11-23-backoff-action-per-leg`.
