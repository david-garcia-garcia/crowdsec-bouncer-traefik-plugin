# Requirement
IssueKey: 2026-09-05-introduce-radix-tree

## Problem

CIDR membership in this plugin is a linear scan. `pkg/ip.Checker` walks every trusted IP and every trusted network on each lookup. Range remediation walks every `range-index` line and calls `ip.InNetwork` per line. Large lists make those request paths O(n). The ticket wants an in-tree radix-tree helper (the traefik-geoblock `iplookup` component) so those lookups are O(prefix bits) instead.

Source: caller spec (`ticket/source.md`). Dest `master`.

## Current (code)

- `Checker.ContainsIP` loops `authorizedIPs` then `authorizedIPsNet` with `net.IPNet.Contains`. Path: `pkg/ip/ip.go` (`ContainsIP`).
- `NewChecker` parses bare IPs into a pointer slice and CIDRs into an `*net.IPNet` slice. Path: `pkg/ip/ip.go` (`NewChecker`). Used at bouncer construction for `ForwardedHeadersTrustedIPs` and `ClientTrustedIPs`. Path: `pkg/bouncer/bouncer.go` (`New`). Config validate builds a Checker and discards it. Path: `pkg/configuration/configuration.go` (`validateParamsIPs`).
- `InNetwork` parses one CIDR or one bare IP per call. Path: `pkg/ip/ip.go` (`InNetwork`). Tests: `pkg/ip/ip_test.go`.
- Range match walks `cidr=remediation` lines and calls `ip.InNetwork` until ban wins. Path: `pkg/decisionscope/range.go` (`MatchRangeFromIndex`).
- Range index is one cache blob, not a tree. Path: `pkg/decisionscope/range.go` (`ApplyRangeBatch`, `RangeIndexKey`). Usage packet tells implementers to avoid a radix tree for that blob. Path: `knowledge/devdocs/core_plugin_decisionscope.md` (Language **Range index** Avoid).
- No `pkg/iplookup` (or other radix helper) in this module. `not found`.
- Plugin module has a single external require; Yaegi loads this tree. Path: `go.mod`. A go-module import of traefik-geoblock is not how this plugin takes code.

## Desired

- Bring the traefik-geoblock `pkg/iplookup` radix helper into this tree (copy/adapt, not a new module dependency) so CIDR-set membership is longest-prefix / O(32) IPv4 and O(128) IPv6 instead of O(n) slice walk.
- Use that helper for `pkg/ip.Checker` trusted-IP / trusted-CIDR lookups (`Contains` / `ContainsIP`). Public Checker API and config keys stay the same.
- Do **not** wire the radix tree into Range remediation this change (`MatchRangeFromIndex` / `range-index` stay as they are). That is a future ticket.

## Affected

- New in-tree lookup unit (expected `pkg/iplookup/` after geoblock, name confirmed in explore/propose).
- `pkg/ip/ip.go` — Checker storage and `ContainsIP`.
- `pkg/ip` tests — Checker membership, including overlapping CIDRs if Checker should keep current “any match” semantics (not longest-prefix *priority*; any containing CIDR is enough).
- `pkg/bouncer/bouncer.go` and `pkg/configuration/configuration.go` only if Checker construction signature changes (not required by the ticket).

## Out of scope

- Range remediation radix (`pkg/decisionscope/range.go`, cache `range-index`). Explicit future work.
- New public Traefik config keys.
- Changing `InNetwork` (single CIDR / bare IP; a tree does not help one network).
- Mock LAPI CIDR helper in `tests/e2e/mock/mocklapi/main.go`.
- The real-stack `.geoblock/` clone used for Country e2e. Path: `.gitignore` (`tests/e2e/real/.geoblock/`).
- Associating values (remediation strings) with CIDRs in the tree. Geoblock `IsContained` returns membership + prefix length only.

## Unknowns

- Exact package/file name in this module (`pkg/iplookup` vs folding into `pkg/ip`).
- Whether Checker keeps a separate exact-IP slice or inserts bare IPs as `/32` and `/128` into the tree (current code treats them as two lists).
- Whether geoblock tests are copied wholesale or rewritten against this module’s names.
- Which other “several places” exist besides Checker; caller named Range and then excluded it.

## Tensions

- Caller named Range remediation as a lookup site, then forbade integrating the tree there in this change. Range stays linear; usage packet Avoid remains true until that future ticket.
- Geoblock `IsContained` returns longest prefix length for priority. Checker today is boolean any-match. Wiring must not invent prefix-priority for trusted IPs unless a later requirement asks.
- `core_plugin_decisions_scopes` stores Range as a string blob for Redis readers. A request-path tree would be a derived structure, not a replacement for that blob — out of scope here, recorded so propose does not “fix” it.
