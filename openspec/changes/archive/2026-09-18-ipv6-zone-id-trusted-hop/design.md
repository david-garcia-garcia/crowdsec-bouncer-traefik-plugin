## Context

See proposal.md — Why. `GetRemoteIP` already owns the client address. `parseIP` is the single parse it, `Contains`, `getIP`, and `InNetwork` already call. Go `TCPAddr.String` owns `RemoteAddr` text (`[fe80::1%eth0]:443`); `net.ParseIP` returns nil when `Zone() != ""` (`knowledge/research/std_go_net_ipv6-zone/`).

## Goals / Non-Goals

**Goals:**
- One strip site so every `parseIP` caller treats a zoned IPv6 host as the address.
- Keep today's `net.IP` 16-byte shape (no `netip` import).
- Keep the public string as received.

**Non-Goals:**
- `NewChecker` pool-entry zones (still `net.ParseIP` on the CIDR list).
- `Family` / `FamilyOfHostOrCIDR` (still `net.ParseIP` on the string).
- #77 cache-key canonicalization.
- A second strip on `GetRemoteIP` or `Contains`.
- `ForwardedHeadersInsecure` path changes (it follows `parseIP` for free).

## Decisions

1. **Strip only in `parseIP`.** Alternative: strip in `GetRemoteIP` / `Contains` — rejected; that reconstructs the same fact and misses `InNetwork`.
2. **Last `%` when the prefix contains `:`, then existing `net.ParseIP`.** Alternative: `netip.ParseAddr` + `WithZone("")` — rejected unless Yaegi required it; no `netip` in-tree today; `net.ParseIP` already yields the 16-byte `net.IP` membership uses. IPv4 with `%` stays fail-closed (no colon).
3. **Do not strip brackets.** `[fe80::1%eth0]` as a hop stays unparseable, same as today's `[2001:db8::1]`.
4. **Public string stays zoned.** Rewriting it is #77-adjacent. Yielded `net.IP` is zone-free.
5. **Regressions on existing `TestCheckerContains` / `TestGetRemoteIP`.** Do not depend on `TestHunt_ZonedIPv6RemoteAddrIsTrustedHop`.
6. **Spec fold** into `core_plugin_ip_radix-lookup` (FindSpecHost). Do not rename that leaf this run.

## Risks / Trade-offs

- [Operators list `fe80::1%eth0` as a NewChecker pool entry] → still fails construction; ticket left that out of scope. Mitigation: docs later if operators hit it.
- [A hop `fe80::1%eth0%foo` after last-`%` cut is still unparseable] → fail-closed. Accepted.

## Migration Plan

None. Existing IPv4 and zone-free IPv6 strings parse as today.

## Open Questions

None — explore decisions stand; see `devstate/explore.md`.
