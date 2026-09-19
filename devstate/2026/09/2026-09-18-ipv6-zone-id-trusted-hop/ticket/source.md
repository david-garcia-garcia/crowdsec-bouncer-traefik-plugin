# Ticket source

parseIP uses net.ParseIP only (`pkg/ip/checker.go:84-91`), which rejects IPv6 zone IDs. RemoteAddr [fe80::1%eth0]:443 with pool fe80::/10 never qualifies as a trusted hop, so X-Forwarded-For is ignored. Proven FAIL: TestHunt_ZonedIPv6RemoteAddrIsTrustedHop. Fix: strip the IPv6 zone before parseIP / Contains / GetRemoteIP so fe80::1%eth0 is fe80::1 for pool membership, hop walk, and the yielded net.IP. Contains("fe80::1%eth0") against fe80::/10 must be true. Include regression tests. Bound the ask to this defect only. Do not take #77 IP cache-key canonicalization.
