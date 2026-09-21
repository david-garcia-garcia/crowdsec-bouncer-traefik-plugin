## Context

See proposal.md — Why. Dest `master` (`2d4acf3`) keeps Checker, PoolStrategy, GetRemoteIP, and InNetwork in `pkg/ip/ip.go`. Checker membership is already unit-tested. GetRemoteIP and the forwarded-header walk are not. Client address owner is `pkg/ip.GetRemoteIP` (explore). Bouncer already calls that then `clientPoolStrategy.Checker.Contains`.

## Goals / Non-Goals

**Goals:**
- Same package `ip`. Hop-trust types in `checker.go`; `InNetwork` in `network.go`.
- Unit tests for GetRemoteIP and the X-Forwarded-For (custom header) walk next to Checker.
- Keep existing InNetwork and Checker tests. Behavior unchanged.

**Non-Goals:**
- Renaming package `ip`.
- Moving `InNetwork` into `pkg/decisionscope`.
- Changing bouncer call sites or Checker/GetRemoteIP algorithms.
- Splitting Checker vs PoolStrategy into extra files.
- Sibling tickets (connection/config file splits, scope headers, remediation codes, decisionscope mode, config snapshot).

## Decisions

1. **`checker.go` + `network.go`.** File named for Checker (the type `bouncer.New` constructs). PoolStrategy and GetRemoteIP sit with Checker (one hop-trust domain). Alternative: `trust.go` — rejected; commandments want the type name. Alternative: four files — rejected; ticket bound ask is two files.

2. **`parseIP` stays in `checker.go`.** Both Contains and InNetwork call it. Same package. Alternative: tiny `ip.go` stub — rejected; leftover mixed file.

3. **Tests: `checker_test.go` + `network_test.go`.** Move existing Checker tests with the type. `TestInNetwork` moves with InNetwork. GetRemoteIP tests cover: no header → RemoteAddr host; right-to-left skip trusted hops; all hops trusted → RemoteAddr; empty segments skipped; custom header name; RemoteAddr without port → error.

4. **Identity:** tests call `GetRemoteIP`. Do not parse `RemoteAddr` in a second helper. Traefik forwarded-headers middleware is a peer, not this plugin’s owner.

5. **Fix GetRemoteIP’s comment** when moving it: it falls back to RemoteAddr; it does not return empty string.

6. **Spec fold** into `core_plugin_ip_radix-lookup` (FindSpecHost). File layout is this design, not a new spec id. The delta specifies the hop-walk already implemented.

## Risks / Trade-offs

- [Yaegi still loads `pkg/ip`] → same package; no new import path.
- [Comment drift on GetRemoteIP] → rewrite the method comment in the same move.

## Migration Plan

No operator YAML change. Rollback is the previous tag.
