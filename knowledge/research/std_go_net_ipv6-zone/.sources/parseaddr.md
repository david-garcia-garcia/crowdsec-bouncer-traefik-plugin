---
url: https://pkg.go.dev/net/netip#ParseAddr
title: netip.ParseAddr and WithZone
fetched: 2026-09-18
authority: official
---

ParseAddr accepts dotted decimal, IPv6, or IPv6 with a scoped addressing zone ("fe80::1cc0:3e8c:119f:c2e1%ens18").

Addr may hold a scoped zone. WithZone("") removes it. As16 returns the 16-byte address without the zone (use Addr.Zone for the zone).

ParsePrefix does not permit IPv6 zones.
