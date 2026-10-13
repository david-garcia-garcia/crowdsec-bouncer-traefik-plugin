# Canonicalize clientRequest.remoteIP at origin; drop IPLookupCacheKey; add real CrowdSec e2e for Ip spelling.

## Why

PR #77 (squash `2fedec6`) keyed the Ip cache on `net.IP.String()` and added `IPLookupCacheKey(remoteIP, ipAddr)` so lookup would not re-parse. That interface is confused: `LookupCachedRemediation` takes both the raw header text and the already-parsed `net.IP` for the same address. After `ServeHTTP` bans a nil `ipAddr` (`tech_trustipfail`), `IPLookupCacheKey` is only `ipAddr.String()`. The live memo still re-parses via `IPCacheKey(remoteIP)` (`pkg/lapi/client_live.go`). Captcha `gateBindIP` still binds the cookie to raw `remoteIP` (`pkg/captcha/gate.go`), so a header spelling change misses the gate — same class of defect #77 fixed for the cache.

#77's proof was unit-only (`pkg/lapi/zzz_ipcachekey_test.go`). There is no real-stack e2e that inserts a CrowdSec Ip decision under a non-canonical spelling and hits the bouncer with another spelling. The real Pester suite (`tests/e2e/real/`, `make e2e_pester`) already talks to a live LAPI (`decision_scopes.Tests.ps1` covers Range/Country, not Ip spelling).

## Desired

1. Keep the three `clientRequest` fields (`ipAddr`, `ipType`, `remoteIP`). Do **not** add `originalRawRemoteIP` or any fourth address field.
2. `GetRemoteIP` still returns `(raw, parsed)`. Canonicalize on `clientRequest` after a successful parse: `req.remoteIP = req.ipAddr.String()`. Before that, `remoteIP` stays the raw text so `tech_trustipfail` / extract-fail logs can show the garbage header.
3. Delete `IPLookupCacheKey`. Lookup keys on the already-canonical `remoteIP` string. `ipAddr` remains only for Range membership (`Contains`). `IPCacheKey` stays on the store/delete path (LAPI decision values are still text).
4. Live memo writes `Set(remoteIP, …)` using that canonical string. Do not `IPCacheKey(remoteIP)` on the request path. LAPI `?ip=` may keep using `remoteIP` (now canonical); CrowdSec matches numerically.
5. Captcha gate bind uses the same canonical `remoteIP` (comes for free if ServeHTTP already canonicalized before Check/ServeHTTP).
6. Amend `openspec/specs/core_plugin_decisions_scopes` so the request-side key is the canonical string owned by `clientRequest`, not a second lookup helper. Fold; do not invent a new spec family unless FindSpecHost says `new`.
7. **Real e2e against CrowdSec**, in `tests/e2e/real/` (Pester + live LAPI), not the mock-LAPI tree. Insert an Ip ban via LAPI/`cscli` under at least: expanded IPv6, upper-case IPv6, IPv4-mapped (`::ffff:x.x.x.x`). Request through Traefik with a different spelling of the same address (forwarded header / XFF as the existing harness already does). Assert ban. Cover stream and live (or none) the way `decision_scopes.Tests.ps1` already splits modes. Also assert a repeated live request does not require a fresh LAPI decision fetch if the harness can observe that; if it cannot, say so on explore and keep the unit guard `TestLiveLookup_MemoHitsOnRepeatedRequests`. Reuse `TestUtils.ps1` helpers. Do not invent a second e2e stack.

## Out of scope

- Cache migration.
- New configuration knobs.
- Range-index CIDR text matching (`10.1.2.0/8` vs `10.0.0.0/8`) — already a different ticket.
- Deleting `AddRange`/`RemoveRange` test wrappers.
- Merging or closing any PR.
- Touching the owner's main checkout.

## Evidence already in tree

- `pkg/bouncer/clientrequest.go`, `pkg/bouncer/bouncer.go` (~160–196)
- `pkg/decisionscope/scope.go` `IPCacheKey` / `IPLookupCacheKey`
- `pkg/decisionscope/lookup.go` `LookupCachedRemediation`
- `pkg/lapi/client_live.go` live memo
- `pkg/lapi/client_decisions.go` store/delete
- `pkg/captcha/gate.go` bindIP string equality
- `pkg/ip/checker.go` `GetRemoteIP`
- `tests/e2e/real/decision_scopes.Tests.ps1`, `mode_stream.Tests.ps1`, `mode_live.Tests.ps1`, `TestUtils.ps1`
- Spec: `openspec/specs/core_plugin_decisions_scopes/spec.md`
- Prior run (do not edit that folder): `devstate/2026/09/2026-09-18-ip-cache-key-canonicalization/`
