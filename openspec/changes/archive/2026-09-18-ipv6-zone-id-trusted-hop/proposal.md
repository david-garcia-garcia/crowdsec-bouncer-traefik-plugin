## Why

A link-local IPv6 peer that Go writes as `[fe80::1%eth0]:443` never counts as a trusted hop: `parseIP` calls `net.ParseIP` only, which rejects the RFC 4007 zone, so `GetRemoteIP` ignores `X-Forwarded-For` and the fallback `net.IP` is nil. Operators who list `fe80::/10` as a trusted hop lose the forwarded client.

## What Changes

- Strip the IPv6 zone inside package-private `parseIP` before `net.ParseIP`, so `Contains`, `GetRemoteIP`, `getIP`, and `InNetwork` treat `fe80::1%eth0` as `fe80::1`.
- Keep the public string as received (`SplitHostPort` host or hop text). Yielded `net.IP` is zone-free.
- Add in-tree regressions on `TestCheckerContains` and `TestGetRemoteIP`.
- **Not BREAKING.** IPv4 and zone-free IPv6 parse the same. NewChecker pool entries, `Family` / `FamilyOfHostOrCIDR`, and cache-key spelling stay as they are.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_ip_radix-lookup`: `parseIP` (the owner GetRemoteIP already calls) SHALL strip an IPv6 zone before membership and the yielded `net.IP`. Callers still reuse GetRemoteIP; they MUST NOT parse `RemoteAddr` again.

## Impact

- `pkg/ip/checker.go` (`parseIP`)
- `pkg/ip/network.go` (`InNetwork` follows `parseIP`)
- `pkg/ip/zzz_checker_test.go`
- `openspec/specs/core_plugin_ip_radix-lookup/spec.md` (archive sync)
