# Issues

- [ ] note large  `knowledge/debt/2026-11-23-appsec-call-ignores-inbound-cancel.md`
  Why: the AppSec listener request does not carry the inbound context, so a client that leaves keeps the call open until `appsecHttpTimeoutSeconds` (pre-existing; found by the 180 s `Test_appsecQuery_hopCancelDoesNotTripGate`).
