# AppSec call is not canceled when the client leaves

IssueKey: 2026-11-23-waf-unknown-length-body
Size: large
Action: note

## Why this follow-up
`appsec.Client.Query` builds the listener request with `http.NewRequest`, not with the inbound request's context, so `httpClient.Do` keeps waiting after the client cancels; only `appsecHttpTimeoutSeconds` ends it. `Test_appsecQuery_hopCancelDoesNotTripGate` (`pkg/appsec/zzz_gate_test.go`) therefore waits the full 30 s timeout on each of its 6 hops (measured 180 s on this branch; that request construction is unchanged from master). ModSec already uses `http.NewRequestWithContext(req.Context(), …)` (`pkg/modsecurity/inspect.go`).

## Why it was not taken
Not part of this ticket's ask (bodies of unknown length). Changing it moves when the AppSec gate records a hop and how a canceled hop is classified, which the parallel run `2026-11-23-backoff-action-per-leg` also edits.

## Risks
A client that leaves still holds an AppSec connection and a gate ticket for up to `appsecHttpTimeoutSeconds`; the AppSec test package takes about 3 minutes.
