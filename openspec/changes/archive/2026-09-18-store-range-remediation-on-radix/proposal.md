## Why

On DestBranch, a stream in-memory Range hit already has the winning prefix from the radix walk, then re-parses every stored CIDR to recover the letter and optional origin. That walk is the request-path CPU cliff (about 53µs / 2k allocs at 1k CIDRs; a miss is already ~26 ns). Store the remediation on the endpoint so a hit stays O(prefix).

## What Changes

- Put the stored remediation (letter, optional U+001F origin) on the radix endpoint of the helper that already matched.
- Keep two helpers (ban, captcha). Ban still wins. Trusted-IP Checker stays a boolean CIDR set.
- Drop the request-path `storedByCIDR` / `ParseCIDR` walk.
- Do not geolocate. Do not change Redis, live/none hydration, or the `range-index` blob format.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_ip_radix-lookup`: Range helpers MAY store the remediation string on the winning endpoint. Trusted-IP Checker MUST stay a boolean set. `AddCIDR` / `IsContained` stay boolean.
- `core_plugin_decisions_scopes`: A Range hit SHALL return the stored string of the winning CIDR from that endpoint. It MUST NOT re-parse stored CIDRs on the request path. Ban-over-captcha, origin suffix, and nil/empty miss stay.

## Impact

- `pkg/iplookup/iplookup.go` (endpoint payload; boolean insert unchanged)
- `pkg/decisionscope/rangemembership.go` (hydrate writes the string onto the node; drop `storedMatchingPrefix`)
- Existing `zzz_range*_test.go` / `zzz_iplookup_test.go` locks
- `knowledge/devdocs/core_plugin_decisionscope.md` and `core_plugin_ip.md` usage after apply
- Stream mode + in-memory cache only. No Redis request-path. No AppSec.
