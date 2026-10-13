---
url: https://github.com/david-garcia-garcia/traefik-geoblock/blob/0c2f46dab0fd6cac90f4db0e4ac2c5d2a58325cf/pkg/iplookup/iplookup_test.go
title: iplookup_test.go
fetched: 2026-09-05
authority: source
ref: github.com/david-garcia-garcia/traefik-geoblock@0c2f46dab0fd6cac90f4db0e4ac2c5d2a58325cf:pkg/iplookup/iplookup_test.go
---

Tests construct via NewIpLookupHelper and query via IsContained. Count and NewEmptyIpLookupHelper are not called directly.

IPv4 longest-prefix: 192.168.1.10 matches /32 over 192.168.1.0/24; 192.168.1.5 matches /24; 8.8.8.8 no match.

IPv6 longest-prefix: 2001:db8:85a3:8d3:1234::1 matches /64 over /48 over /32; ::1 matches /128.

Mixed v4/v6 in one helper: 192.168.1.0/24, 2001:db8::/32, 10.0.0.0/8, ::1/128. IPv4 and IPv6 queries succeed or miss independently.

Empty CIDR list: no IP matches.

Invalid CIDRs error NewIpLookupHelper: invalid-cidr, 192.168.1.0/33, 2001:db8::/129, 192.168.1 (no prefix), empty string.

OverlappingRanges / PrefixLengthAccuracy: most-specific prefixLen is the returned length (e.g. 192.168.1.10 → 32, 192.168.1.5 → 24, 10.1.1.1 → 16). Catch-all 0.0.0.0/0 and ::/0 match remaining addresses with prefix 0.

EdgeCases: 0.0.0.0/0, 255.255.255.255/32, ::/0 in one helper; IPv4 and IPv6 test IPs all match.
