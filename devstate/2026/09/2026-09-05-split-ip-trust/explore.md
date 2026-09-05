# Explore
IssueKey: 2026-09-05-split-ip-trust

Measured: `go test ./pkg/ip` passed (1.185s) on dest `master` (`2d4acf3`). `TestInNetwork`, `TestCheckerContains`, and `TestCheckerContainsCatchAllFamily` exist. No `TestGetRemoteIP`. Not a reproduced product bug — a file-split plus a missing hop-walk test.

Consumed: `knowledge/devdocs/core_plugin_ip.md`, `core_plugin_middleware.md`. Research indexes have no Traefik X-Forwarded-For finding; this run tests **this** package’s `GetRemoteIP`, not Traefik’s ipstrategy. No new `knowledge/research/` write.

```
pkg/ip today (one file)
┌──────────────────────────────────────────────┐
│  Checker / NewChecker / Contains              │  trusted hop + client lists
│  PoolStrategy.getIP  ── XFF right-to-left    │  hop-trust walk
│  GetRemoteIP         ── then RemoteAddr       │  client address owner
│  InNetwork           ── one CIDR or bare IP   │  Range blob line
│  parseIP             ── shared private       │
└──────────────────────────────────────────────┘

desired (same package)
┌─────────────────────────────┐   ┌──────────────────┐
│ checker.go                   │   │ network.go      │
│ Checker, PoolStrategy,       │   │ InNetwork        │
│ GetRemoteIP, parseIP helper  │   │ (+ existing      │
│ checker_test.go              │   │  TestInNetwork)  │
│  Contains + GetRemoteIP/XFF │   │ network_test.go  │
└─────────────────────────────┘   └──────────────────┘
         ▲
         │ bouncer.ServeHTTP still imports pkg/ip
```

## Concepts

**Trusted-IP Checker** (existing Language): pool from `ForwardedHeadersTrustedIPs` or `ClientTrustedIPs`. Boolean any-match via `pkg/iplookup`.

**GetRemoteIP**: owner of the client address for every request. Walks the custom forwarded header (default `X-Forwarded-For`) most-recent-first against the **server** pool (`ForwardedHeadersTrustedIPs`). First address **not** in that pool is the client. Empty walk → `net.SplitHostPort(req.RemoteAddr)`. `Bouncer` then asks the **client** pool (`ClientTrustedIPs`) `Contains` on that same string. Do not parse `RemoteAddr` a second time.

**InNetwork**: one address vs one CIDR/bare IP. Range blob lines, not the trusted pool. Stays in `pkg/ip`.

Ticket nickname “hop-trust” is not Language. Types stay Checker, PoolStrategy, GetRemoteIP.

## Decisions

- Same package `ip`. Two files, not four. Ticket bound ask wins over splitting Checker vs PoolStrategy into extra files.
- File names: `checker.go` / `checker_test.go` (Checker is the type the bouncer constructs) and `network.go` / `network_test.go`. Delete `ip.go` / `ip_test.go` after the move (no stub).
- `parseIP` stays package-private in `checker.go` (Contains and InNetwork both call it).
- Move existing Checker tests with the type. Add GetRemoteIP tests in `checker_test.go`: no header → RemoteAddr host; XFF right-to-left skip trusted hops; all hops trusted → RemoteAddr; empty segments skipped; custom header name; RemoteAddr without port → error.
- When moving `GetRemoteIP`, fix its comment: it does not return empty string; it falls back to RemoteAddr.
- Spec: fold into `core_plugin_ip_radix-lookup` (already owns Checker + GetRemoteIP). Do not invent `core_plugin_ip_hop-trust`. Do not move InNetwork into `decisionscope`.
- Usage packet `core_plugin_ip.md` Key files updates after the split (implement / devdocsimpact). No Language write this phase — terms already exist.
- Bouncer call sites unchanged.

## Open questions

- Q: Exact file names (`trust.go` vs another stem) and where package-private `parseIP` lives?
  Decision: resolved — `checker.go` + `network.go`. `parseIP` in `checker.go`. Delete leftover `ip.go`.
  By: explore

- Q: Whether `ip.go` remains as a package-comment stub or is deleted after the split?
  Decision: resolved — delete. Package comment moves to `checker.go`.
  By: explore

- Q: Whether existing Checker tests stay in `ip_test.go` or move to a trust test file?
  Decision: resolved — move to `checker_test.go`. `TestInNetwork` moves to `network_test.go`.
  By: explore

- Q: Who already owns the client address (identity) for this change?
  Decision: resolved — `pkg/ip.GetRemoteIP` is the owner. Tests and bouncer reuse that output. Do not parse `RemoteAddr` in a second helper. Traefik’s own forwarded-headers middleware is a peer, not the owner this plugin classifies.
  By: explore

- Q: New spec leaf vs fold into `core_plugin_ip_radix-lookup`?
  Decision: resolved — fold. Spec delta is GetRemoteIP hop-walk (ADDED). File names stay in design.md (`checker.go` / `network.go`), not a new spec id.
  By: propose
