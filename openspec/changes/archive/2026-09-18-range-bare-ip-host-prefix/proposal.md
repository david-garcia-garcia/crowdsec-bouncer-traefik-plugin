## Why

A Range decision whose host is a parseable bare IP is written onto `range-index` and then skipped: `AddCIDR` is `net.ParseCIDR` only, so that address is never remediated. CrowdSec persist already accepts a bare IP or a CIDR on Range; the trusted pool already maps a bare IP to `/32` or `/128` before insert.

## What Changes

- Treat a parseable Range host as `/32` (IPv4) or `/128` (IPv6) at index upsert, remove, and membership rebuild.
- Reuse the trusted-pool host-prefix mapping from `pkg/ip`. Do not change `NewChecker`.
- Add one spec scenario and a regression test that a Range host `192.0.2.1` remediates that address.
- **Not BREAKING.** CIDR Range values and unparseable lines stay as they are.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_decisions_scopes`: a parseable Range host is a `/32` or `/128` CIDR and remediates that address.

## Impact

- `pkg/ip` (export the existing host-prefix mapping)
- `pkg/decisionscope` (`ApplyRangeBatch`, `MembershipFromIndex`)
- `pkg/decisionscope` Range / membership tests
- `openspec/specs/core_plugin_decisions_scopes/spec.md`
