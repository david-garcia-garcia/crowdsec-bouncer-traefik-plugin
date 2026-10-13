# Requirement
IssueKey: 2026-09-18-range-hit-origin

## Problem
In stream mode with the in-memory DecisionStore, a Range HIT is the request-path CPU cliff. `RangeMembership.Remediation` already has the winning `prefixLen` from `iplookup.Helper.IsContained`, then `storedMatchingPrefix` walks every CIDR in `storedByCIDR` and `net.ParseCIDR` + `Contains` each one to recover the stored letter plus optional origin. Ticket-measured (compiled Go): 1k CIDRs ≈ 40µs / 1986 allocs; 10k CIDRs ≈ 450µs / 19623 allocs. A Range miss is already ~26 ns / 0 allocs.

## Current (code)
- `RangeMembership` keeps two boolean helpers (`ban`, `captcha`) plus `storedByCIDR` (`cidr` → letter or letter plus U+001F origin). `pkg/decisionscope/rangemembership.go`
- `MembershipFromIndex` `AddCIDR`s the line then stores the raw remediation string under the blob CIDR text. Invalid CIDR lines are skipped. `pkg/decisionscope/rangemembership.go`
- `Remediation` returns `""` when membership or IP is nil, or when neither helper contains the IP. On a hit it calls `storedMatchingPrefix` with the helper’s `prefixLen`. `pkg/decisionscope/rangemembership.go`
- `storedMatchingPrefix` iterates `storedByCIDR`, `net.ParseCIDR`s each key, `Contains`s the IP, and returns the first stored string whose mask `ones` equals `prefixLen`; else any containing CIDR of that kind; else the kind letter. `pkg/decisionscope/rangemembership.go`
- `radixNode` stores `isEndpoint` and `prefixLen` only. `insert` does not keep a remediation. `IsContained` returns found + longest prefix length, not a stored string. `pkg/iplookup/iplookup.go`
- Trusted-IP `Checker` also uses `iplookup.Helper` as a boolean set (no origin). `pkg/ip/checker.go`
- Request lookup calls `membership.Remediation`; nil or empty membership is a Range miss. Ban wins over captcha across Ip / Range / headers. `pkg/decisionscope/lookup.go`
- Stream/alone hydrate membership from the `range-index` blob; live/none do not. `pkg/lapi/client.go` `pkg/lapi/client_stream.go`
- Existing tests lock ban-over-captcha, origin suffix, longest-prefix origin, nil/empty miss, IPv4-mapped non-panic. `pkg/decisionscope/zzz_rangemembership_test.go` `pkg/decisionscope/zzz_range_test.go`
- Ticket µs/alloc numbers are not in this tree. `not found`

## Desired
- Put the stored remediation (letter, optional U+001F origin) on the radix endpoint so a Range hit is O(prefix), not O(n) `ParseCIDR`.
- Behavior stays the same: ban wins over captcha; origin is the winning CIDR’s stored suffix; nil/empty membership is a miss.
- Do not geolocate.
- Do not change Redis, live/none hydration, or the range-index blob format unless required to keep request-path lookup correct.
- Stream mode + in-memory cache only. Do not add Redis to the design.

## Affected
- `pkg/decisionscope/rangemembership.go` (`storedMatchingPrefix`)
- `pkg/iplookup/iplookup.go`
- `pkg/decisionscope/zzz_rangemembership_test.go` `pkg/decisionscope/zzz_range_test.go`
- `knowledge/devdocs/core_plugin_decisionscope.md`

## Out of scope
- Redis request-path
- `cache.ErrMiss` sentinel
- lazy slog
- AppSec
- `ttl_map` lock redesign
- Yaegi
- Adding Redis to the design
- Geolocate
- Changing Redis, live/none hydration, or the range-index blob format unless required for request-path lookup correctness

## Unknowns
- Whether `Helper.AddCIDR` grows an optional payload or a new insert path is added; trusted-IP `Checker` must stay a boolean set.
- Whether `storedByCIDR` remains after the endpoint holds the string, or is dropped because the request path no longer walks it.
- Whether a prefixLen vs stored-key `ones` mismatch (IPv4-mapped `/96` vs remapped IPv4 `0`) still needs the old fallback once the winning node carries the payload.

## Tensions
- Usage packet still says Range membership is two boolean CIDR sets plus a stored string per CIDR, and Avoids “one LPM tree with a stored remediation”. `knowledge/devdocs/core_plugin_decisionscope.md`
- Ticket asks to store letter+origin on the radix endpoint. It still requires ban-over-captcha and does not ask to collapse the two helpers into one tree.
- Archived IPv4-mapped design kept `storedMatchingPrefix` as the fallback when node `prefixLen` and blob `ones` disagree. Putting the payload on the node removes that walk if insert stores the string at the same endpoint `IsContained` reports.
