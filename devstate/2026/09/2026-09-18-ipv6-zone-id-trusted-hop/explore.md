# Explore

## Concepts

```
  Go net/http socket peer
  TCPAddr.String → [fe80::1%eth0]:443
           │
           ▼
  GetRemoteIP  (owner of client address)
     SplitHostPort → host fe80::1%eth0
     parseIP(host) → net.ParseIP  ← rejects %zone (nil)
           │
           ├─ trustedPeer false
           └─ ignore X-Forwarded-For
              return "fe80::1%eth0", nil net.IP
           │
           ▼
  ServeHTTP: ipAddr == nil → plugin:tech_trustipfail
```

**GetRemoteIP** is already the owner of the client address. The defect is inside package-private `parseIP` that GetRemoteIP, `Contains`, `getIP`, and `InNetwork` already call. Traefik `ipstrategy` is not a second owner (`core_plugin_ip` `_Avoid_`). Go `TCPAddr.String` owns the `RemoteAddr` *text* (zone included); this plugin must consume that text, not re-derive the peer.

**Zone ID** is RFC 4007 scope (`%eth0`, `%12`). `net.SplitHostPort` keeps `host%zone`. `net.ParseIP` returns nil when `Zone() != ""` even though `netip.ParseAddr` accepts the same string (`knowledge/research/std_go_net_ipv6-zone/`).

**Reproduction**
- `TestHunt_ZonedIPv6RemoteAddrIsTrustedHop`: **not-run** — `go test ./pkg/ip -run TestHunt_ZonedIPv6RemoteAddrIsTrustedHop -count=1` → `ok … [no tests to run]`.
- Equivalent throwaway (temp module, `pkg/ip` via replace): **fail**. `Contains("fe80::1%eth0")` → `false` / `parseIP:parseAddress`. `GetRemoteIP` on `RemoteAddr=[fe80::1%eth0]:443`, pool `fe80::/10`, header `X-Forwarded-For: 203.0.113.10` → `"fe80::1%eth0"`, nil `net.IP`, nil error (wanted `203.0.113.10`).
- Existing `TestGetRemoteIP` / `TestCheckerContains`: **pass**. No zoned case.

## Decisions

- Strip the zone inside package-private `parseIP` only. Do not add a second strip on `GetRemoteIP` or `Contains`. `InNetwork` follows for free.
- Strip by cutting the last `%` when the prefix contains `:`, then call existing `net.ParseIP` so the yielded `net.IP` keeps today’s 16-byte shape. Do not import `netip` unless propose shows Yaegi needs it.
- Keep the public string as received (`SplitHostPort` host or hop text). Do not rewrite `%eth0` off the string (avoids #77 cache-key work). Yielded `net.IP` is zone-free.
- A zoned hop in the forwarded header: return the original hop text plus the stripped parse, same as any other hop.
- Do not strip brackets. `[fe80::1%eth0]` as a hop stays fail-closed.
- In-tree regressions on `TestCheckerContains` and `TestGetRemoteIP` (or siblings in `zzz_checker_test.go`). Do not depend on the Hunt_ name.
- Spec delta folds into existing `core_plugin_ip_radix-lookup`. Do not rename `core_plugin_ip` / that spec.
- No `knowledge/devdocs` write this phase. Usage is enough to call GetRemoteIP; zone strip is a gotcha for implement / devdocsimpact after apply.
- Bound: this defect only. No `NewChecker` pool-entry zones, no `Family` / `FamilyOfHostOrCIDR`, no insecure-only path, no #77.

## Open questions

- Q: Who already owns the client address / trust hop this change would reconstruct?
  Decision: resolved — `pkg/ip.GetRemoteIP` is the in-product owner. Go `net/http` via `TCPAddr.String` owns `req.RemoteAddr` text (including `%zone`). Traefik `ipstrategy` is not the owner. Reuse GetRemoteIP; strip inside `parseIP` that it already calls. Do not parse `RemoteAddr` in a neighbor. Spec uses GetRemoteIP output only.
  By: propose

- Q: Should the GetRemoteIP **string** for a zoned RemoteAddr fallback keep `%eth0` or become `fe80::1`?
  Decision: assumed — keep `fe80::1%eth0` (the `SplitHostPort` host). Ticket names membership, hop walk, and yielded `net.IP` only. Rewriting the string is #77-adjacent.
  By: propose

- Q: Should a zoned hop in the forwarded header return the original hop text or the stripped address?
  Decision: assumed — original hop text plus stripped `net.IP`, same as today’s unparseable-then-parseable hop contract after the strip lands.
  By: propose

- Q: How should `parseIP` strip the zone?
  Decision: resolved — last `%` on an IPv6-looking string (prefix contains `:`), then existing `net.ParseIP`. No `netip` in-tree; Yaegi gap not measured because this path does not import `netip`.
  By: propose
