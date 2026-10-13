## Why

After #77 the Ip cache already keys on `net.IP.String()`, but DestBranch still keeps the raw forwarded-header text on `clientRequest.remoteIP`. Lookup takes that raw string plus the parsed address. The live memo re-parses the raw text. The captcha gate cookie binds the raw spelling. A later request that spells the same address differently can miss the gate, and there is no real CrowdSec e2e that inserts an Ip ban under one spelling and hits Traefik with another.

## What Changes

- After a successful `GetRemoteIP` parse, `clientRequest.remoteIP` becomes `ipAddr.String()`. Before that, `remoteIP` stays the raw header so extract-fail / `tech_trustipfail` logs can show the garbage text. No fourth address field.
- Delete `IPLookupCacheKey`. Request lookup keys on that already-canonical `remoteIP`. `ipAddr` remains only for Range membership. `IPCacheKey` stays on the LAPI store/delete path.
- Live memo writes `Set(remoteIP, …)` and MUST NOT call `IPCacheKey` on the request path. LAPI `?ip=` keeps using `remoteIP` (now canonical).
- Captcha gate bind uses the same canonical `remoteIP` (ServeHTTP canonicalizes before Check/ServeHTTP).
- Fold `core_plugin_decisions_scopes` so the request-side key is the canonical string owned by `clientRequest`, not a second lookup helper.
- Real e2e in `tests/e2e/real/`: insert Ip bans under expanded IPv6, upper-case IPv6, and IPv4-mapped; request a different spelling via XFF; assert ban in none and stream. Live memo-hit stays a unit guard.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_decisions_scopes`: the request-side Ip key is the canonical string on `clientRequest` after a successful parse, not a second lookup helper derived at read time.

## Impact

- `pkg/bouncer/bouncer.go` (canonicalize after parse)
- `pkg/decisionscope/scope.go`, `lookup.go` (delete `IPLookupCacheKey`; key on `remoteIP`)
- `pkg/lapi/client_live.go` (memo `Set(remoteIP)`)
- `pkg/captcha/gate.go` unchanged if ServeHTTP already canonicalized
- `openspec/specs/core_plugin_decisions_scopes/spec.md`
- Units that name `IPLookupCacheKey`; keep `TestLiveLookup_MemoHitsOnRepeatedRequests`
- `tests/e2e/real/decision_scopes.Tests.ps1` plus `TestUtils.ps1` helpers already there
- No new config. No cache migration. No mock-LAPI suite.
