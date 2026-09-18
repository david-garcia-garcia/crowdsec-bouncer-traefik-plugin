# Requirement
IssueKey: 2026-09-18-canonicalize-client-remoteip

## Problem

PR #77 made Ip cache keys `net.IP.String()` and added `IPLookupCacheKey(remoteIP, ipAddr)` so lookup would not re-parse. The request path still carries the same address twice (raw header text plus parsed `net.IP`). Live memo still re-parses via `IPCacheKey(remoteIP)`. Captcha gate bind still compares the raw `remoteIP` string. Proof is unit-only; there is no real-stack e2e that inserts a CrowdSec Ip decision under one spelling and hits Traefik with another.

## Current (code)

- `pkg/bouncer/clientrequest.go` — three fields only: `ipAddr`, `ipType`, `remoteIP`.
- `pkg/ip/checker.go` — `GetRemoteIP` returns `(raw string, parsed net.IP, error)`.
- `pkg/bouncer/bouncer.go` — copies raw `remoteIP` onto `clientRequest` and never assigns `req.ipAddr.String()` after a successful parse. Nil `ipAddr` bans as `tech_trustipfail` and returns before lookup.
- `pkg/decisionscope/scope.go` — `IPCacheKey` canonicalizes decision-value text; `IPLookupCacheKey` keys on `ipAddr.String()` when parsed, else trimmed `remoteIP`.
- `pkg/decisionscope/lookup.go` — `LookupCachedRemediation` / `LookupCacheKeys` take both raw `remoteIP` and `ipAddr` and call `IPLookupCacheKey`.
- `pkg/lapi/client_live.go` — live memo `Set` uses `IPCacheKey(remoteIP)`; LAPI query is `ip=<remoteIP>`.
- `pkg/lapi/client_decisions.go` — stream store/delete still key Ip slots with `IPCacheKey(item.Value)`.
- `pkg/captcha/gate.go` — bind is string equality on the `remoteIP` passed in.
- `pkg/bouncer/bouncer.go` — captcha `Check` / `ServeHTTP` receive `req.remoteIP`.
- `pkg/lapi/zzz_ipcachekey_test.go` — unit proof including `TestLiveLookup_MemoHitsOnRepeatedRequests`.
- `tests/e2e/real/decision_scopes.Tests.ps1` — live LAPI Range/Country only; no Ip spelling cases.
- `tests/e2e/real/TestUtils.ps1` — `Add-TestIPDecision` / `Test-HttpRequest` (XFF) already exist.
- `openspec/specs/core_plugin_decisions_scopes/spec.md` — request-side key is derived by a lookup helper from `GetRemoteIP`'s `net.IP`.
- `knowledge/research/ext_crowdsec_decisions_scopes/notes.md` — LAPI `?ip=` matches numerically; CrowdSec stores decision values verbatim.

## Desired

1. Keep the three `clientRequest` fields. Do not add a fourth address field.
2. `GetRemoteIP` still returns `(raw, parsed)`. After a successful parse, `req.remoteIP = req.ipAddr.String()`. Before that, `remoteIP` stays raw so extract-fail / `tech_trustipfail` logs show the garbage header.
3. Delete `IPLookupCacheKey`. Lookup keys on the already-canonical `remoteIP` string. `ipAddr` remains only for Range membership. `IPCacheKey` stays on the LAPI store/delete path.
4. Live memo writes `Set(remoteIP, …)` with that canonical string. Do not `IPCacheKey(remoteIP)` on the request path. LAPI `?ip=` may keep using `remoteIP` (now canonical).
5. Captcha gate bind uses that same canonical `remoteIP`.
6. Fold `openspec/specs/core_plugin_decisions_scopes` so the request-side key is the canonical string owned by `clientRequest`, not a second lookup helper.
7. Real e2e in `tests/e2e/real/` (Pester + live LAPI): insert an Ip ban via LAPI/`cscli` under at least expanded IPv6, upper-case IPv6, and IPv4-mapped (`::ffff:x.x.x.x`); request through Traefik with a different spelling (existing XFF harness); assert ban; cover stream and live (or none) the way `decision_scopes.Tests.ps1` splits modes. Repeated live fetch observability: if the harness cannot see it, say so on explore and keep `TestLiveLookup_MemoHitsOnRepeatedRequests`. Reuse `TestUtils.ps1`. No second e2e stack.

## Affected

- `pkg/bouncer/bouncer.go`, `pkg/bouncer/clientrequest.go`
- `pkg/decisionscope/scope.go`, `pkg/decisionscope/lookup.go`
- `pkg/lapi/client_live.go`
- `pkg/captcha/gate.go` (bind string; no API change if ServeHTTP already canonicalized)
- `openspec/specs/core_plugin_decisions_scopes/spec.md`
- `tests/e2e/real/` (new Ip-spelling cases; helpers already in `TestUtils.ps1`)
- Unit tests that name `IPLookupCacheKey`

## Out of scope

- Cache migration.
- New configuration knobs.
- Range-index CIDR text matching (`10.1.2.0/8` vs `10.0.0.0/8`).
- Deleting `AddRange` / `RemoveRange` test wrappers.
- Merging or closing any PR (including #77).
- Touching the owner's main checkout.
- Changing `GetRemoteIP`'s return shape.
- Mock-LAPI e2e (`tests/e2e/mock/`).

## Unknowns

- Whether the real Pester harness can observe that a repeated live request does not trigger a fresh LAPI decision fetch.
- How `cscli decisions add --ip` stores IPv4-mapped and expanded IPv6 text on the fixture image (CrowdSec stores values verbatim; exact `cscli` spelling of `::ffff:…` is for explore).

## Tensions

- Ticket says after `ServeHTTP` bans a nil `ipAddr`, `IPLookupCacheKey` is only `ipAddr.String()`. Code: that ban returns before lookup (`pkg/bouncer/bouncer.go`). `IPLookupCacheKey` with a nil `ipAddr` falls back to trimmed `remoteIP`, not `ipAddr.String()`.
- Spec today requires the request-side key to be derived by a helper from the already-parsed `net.IP`. Ticket asks to fold that so `clientRequest.remoteIP` is the key after canonicalize-at-origin.
