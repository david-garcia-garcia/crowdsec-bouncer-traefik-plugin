# Trusted-IP lookup

## Language

**Trusted-IP Checker**:
The pool built from `ForwardedHeadersTrustedIPs` or `ClientTrustedIPs`. `Contains` / `ContainsIP` answer whether an address is in that pool.
_Avoid_: Range index, LAPI decision value, geolocation

**IP lookup helper**:
In-tree radix of CIDRs (`pkg/iplookup.Helper`). Insert at construction; `IsContained` is membership plus longest prefix length. No associated remediation.
_Avoid_: range-index, per-CIDR cache key, `InNetwork` (one network)

## Overview

Use `pkg/ip.NewChecker` for trusted hop and trusted client lists. The Checker stores those CIDRs in `pkg/iplookup`. Use `ip.InNetwork` when the question is one CIDR (Range lines). Do not parse `RemoteAddr` in the helper; classify `GetRemoteIP`.

## How to use

- Build the Checker once in `bouncer.New` from config lists.
- Call `Contains` / `ContainsIP` on the request path. Do not walk a CIDR slice beside the helper.
- Convert a bare IP to `/32` or `/128` before `AddCIDR`.
- Leave Range matching on `decisionscope.MatchRangeFromIndex` (`InNetwork` per line) until a later change.

## Pattern snippet

```go
checker, err := ip.NewChecker(log, config.ClientTrustedIPs)
ok, err := checker.Contains(remoteIP)
```

## Key files

- `pkg/ip/ip.go`
- `pkg/iplookup/`
- `pkg/bouncer/bouncer.go`
- `pkg/configuration/configuration.go` (`validateParamsIPs`)

## Gotchas

- `IsContained` prefix length is for longest-match callers. Checker is boolean any-match.
- The helper does not store remediation strings. Range ban/captcha cannot ride this tree yet.
- Invalid CIDR fails `NewChecker` / `AddCIDR`; config validate already constructs a Checker and discards it.
- `0.0.0.0/0` is IPv4 only; `::/0` is IPv6 only. A shared radix root would mark `/0` on both families.
