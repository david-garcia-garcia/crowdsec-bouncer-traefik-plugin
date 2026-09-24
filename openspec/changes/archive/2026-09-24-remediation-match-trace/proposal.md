## Why

TRACE ServeHTTP on a remediating request shows the client IP, leftover `cache=hit`, and a remediation letter. That does not tell the operator which mapped CrowdSec scopes (Country, AS, and the rest of `bouncerDecisionScopeHeaders`) were in play. Cache is not the operator-facing model.

## What Changes

- Keep logging the client IP on TRACE ServeHTTP. Reuse `GetRemoteIP` / `clientRequest.remoteIP` and the `RequestScopeValues` map already collected. Do not re-parse `RemoteAddr` or re-read headers at log time.
- Drop leftover `cache` from the remediating `ServeHTTP` TRACE. Keep `remediation` (letter). Leave DEBUG `ServeHTTP:Get` `cache` (lookup error) unchanged.
- When a store-hit or live-lookup remediation fires, attach present `RequestScopeValues` as a slog group `scopes`. Omit missing headers. Do not log a winner or a Range CIDR.
- `ServeHTTP:LiveLookup` gets the same `ip` + `scopes` + kind (`isBanned` stays). `handleRemediationServeHTTP` stays `ip` + `remediation`.
- Keep the first-breadcrumb SHALL (`ServeHTTP` stem, `ip`, `isTrusted`). Do not require `scopes` on the allow/trust line.
- Extend `pkg/bouncer/zzz_debug_attrs_test.go` for the remediating lines.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `std_go_logger_debug-attrs`: remediating TRACE must not present a cache hit; it must include present mapped scope values. First breadcrumb `ip` + `isTrusted` + stem `ServeHTTP` stay.

## Impact

- `pkg/bouncer/bouncer.go` — remediating `ServeHTTP` TRACE and `ServeHTTP:LiveLookup` TRACE.
- `pkg/bouncer/zzz_debug_attrs_test.go` — TRACE attribute assertions.
- Live catalog fold only: `openspec/specs/std_go_logger_debug-attrs/spec.md`.
- Usage How-to still shows the DestBranch cache-hit example; implement / `opd-devdocsimpact` updates that line.
- No public config keys. No lookup-return reshape. No Range CIDR on TRACE.
