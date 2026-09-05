## Why

Trusted-IP and trusted-CIDR membership walks every configured network on each request. Operators with large `ForwardedHeadersTrustedIPs` or `ClientTrustedIPs` lists pay O(n) for a boolean that a radix tree answers in O(prefix bits). This module has no such helper; traefik-geoblock already does.

## What Changes

- Add in-tree `pkg/iplookup` (copy/adapt traefik-geoblock radix helper as `Helper`). No new Go module.
- `pkg/ip.Checker` stores CIDRs in that helper. Bare IPs become `/32` or `/128`. `Contains` / `ContainsIP` stay the public API.
- Do **not** change Range remediation (`range-index` / `MatchRangeFromIndex`). That stays linear.
- No new public Traefik config keys. **Not BREAKING.**

## Capabilities

### New Capabilities

- `core_plugin_ip_radix-lookup`: Trusted-IP Checker membership uses an in-tree CIDR radix helper (boolean any-match, O(prefix bits)).

### Modified Capabilities

None.

## Impact

- New `pkg/iplookup/` (Helper + tests).
- `pkg/ip/ip.go` Checker construction and `ContainsIP`.
- `pkg/bouncer` and `pkg/configuration` keep calling `NewChecker`; no signature change required.
- `pkg/decisionscope/range.go` unchanged.
- Usage packet `knowledge/devdocs/core_plugin_ip.md`.
