# Trusted-IP lookup

## Language

**Trusted-IP Checker**:
The pool built from `ForwardedHeadersTrustedIPs` or `ClientTrustedIPs`. `Contains` / `ContainsIP` answer whether an address is in that pool.
_Avoid_: Range index, LAPI decision value, geolocation

**IP lookup helper**:
In-tree radix of CIDRs (`pkg/iplookup.Helper`). Insert at construction; `IsContained` is membership plus longest prefix length. No associated remediation.
_Avoid_: range-index, per-CIDR cache key, `InNetwork` (one network)

**GetRemoteIP**:
The owner of the client address for a request. Walks the custom forwarded header most-recent-first against the trusted-hop pool, then the host of `RemoteAddr`. Also yields that address as `net.IP` when parseable.
_Avoid_: parsing `RemoteAddr` on the connection, a second X-Forwarded-For walk, Traefik ipstrategy as a second owner

**clientRequest**:
The inbound request plus the client address GetRemoteIP already chose (`remoteIP` string, `ipAddr` net.IP, `ipType` for metrics). Handlers keep the parameter name `req`.
_Avoid_: renaming `req` to `client`; a bag for scopes, origin, or captcha state; `context.Value`

## Overview

Use `pkg/ip.NewChecker` for trusted hop and trusted client lists. The Checker stores those CIDRs in `pkg/iplookup`. Stream/alone Range uses two Helpers on CrowdsecConnection (ban set, captcha set), not Checker. Use `ip.InNetwork` when the question is one CIDR (blob line parse). Do not parse `RemoteAddr` in the helper; classify `GetRemoteIP`.

## How to use

- Build the Checker once in `bouncer.New` from config lists.
- Resolve the client address with `GetRemoteIP` (server/trusted-hop pool + custom header). Put that string, `ipAddr`, and `FamilyOfIP` on `clientRequest`. Keep the name `req`. Then `ContainsIP` on `req.ipAddr` for the client pool. Do not parse `RemoteAddr` again. Do not parse the chosen string again for trusted-client membership. Do not add scopes or origin to `clientRequest`.
- On the request path, call `ContainsIP` on the parsed GetRemoteIP address. `Contains` remains for string callers. Do not walk a CIDR slice beside the helper.
- Convert a bare IP to `/32` or `/128` before `AddCIDR`.
- Range stream/alone membership reuses `Helper` as two boolean sets on the connection. Do not put Range in Checker.
- One-CIDR questions (`InNetwork`) live in `pkg/ip/network.go`, not in Checker.
- Classify an already-parsed address with `FamilyOfIP` for usage-metrics `ip_type`. Keep `Family` / `FamilyOfHostOrCIDR` for decision values. Do not parse `RemoteAddr`.

## Pattern snippet

```go
checker, err := ip.NewChecker(log, config.ClientTrustedIPs)
ok := checker.ContainsIP(req.ipAddr)
```

## Key files

- `pkg/ip/checker.go`
- `pkg/ip/network.go`
- `pkg/iplookup/`
- `pkg/bouncer/clientrequest.go`
- `pkg/bouncer/bouncer.go`
- `pkg/configuration/configuration.go` (`validateParamsIPs`)

## Gotchas

- `IsContained` prefix length is for longest-match callers. Checker is boolean any-match.
- The helper does not store remediation strings. Range ban and captcha are two Helpers, not one payload tree.
- Invalid CIDR fails `NewChecker` / `AddCIDR`; config validate already constructs a Checker and discards it.
- `0.0.0.0/0` is IPv4 only; `::/0` is IPv6 only. A shared radix root would mark `/0` on both families.
