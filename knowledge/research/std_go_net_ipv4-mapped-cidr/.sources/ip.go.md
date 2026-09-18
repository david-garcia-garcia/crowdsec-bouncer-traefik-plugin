---
url: https://github.com/golang/go/blob/go1.25.6/src/net/ip.go
title: net.IP.To4, IPNet.Contains, ParseCIDR
fetched: 2026-09-18
authority: source
ref: golang/go@go1.25.6:src/net/ip.go
---

`To4()`: 4-byte IP returned as-is. 16-byte IP whose `[0:10]` is zeros and `[10]==0xff` and `[11]==0xff` returns `[12:16]`. Else nil.

`networkNumberAndMask`: if `n.IP.To4()` is non-nil, the network number is that 4-byte IP. When the mask length is 16, the mask becomes `m[12:]`.

`Contains`: `networkNumberAndMask` on the network; query `To4()` when non-nil; false when lengths differ; else byte-wise `nn&m == ip&m`.

`ParseCIDR`: parse addr with `netip.ParseAddr`, prefix `n` must be `0..BitLen()` (128 for IPv6 including IPv4-mapped). Mask is `CIDRMask(n, BitLen())`. Network IP is `addr16.Mask(m)` — still 16 bytes.

`String()` uses `networkNumberAndMask` then `simpleMaskLength`, so a mapped `/96` prints as IPv4 `/0`.

Also: https://pkg.go.dev/net#IPNet.Contains (authority: official) — Contains reports whether the network includes ip.
