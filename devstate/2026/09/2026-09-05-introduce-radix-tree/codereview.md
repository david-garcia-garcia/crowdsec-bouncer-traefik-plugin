# Code review
Pin: origin/master...HEAD excluding destate/ and .cursor/

Late axis reports arrived after the first aggregate (`none`). This file now holds those reports and the unattended hard fixes.

## Standards
1. [hard] Name for the scope — `pkg/ip/ip.go:20` — `helper` is `iplookup.Helper`’s type nickname, not the trusted CIDR set `NewChecker` / `ContainsIP` hold
 → Rename the field and the `NewChecker` local to `trustedCIDRs`

2. [hard] Leave a trail — `pkg/ip/ip.go:62` — `ContainsIP` is now three blocks (nil helper, any-match, error) with no intros; it drops longest-prefix and collapses `IsContained`’s nil-IP error to `false`
 → Comment that Checker is boolean any-match (ignore prefix length) and that nil IP is not trusted

3. [hard] Leave a trail — `pkg/ip/ip.go:38` — the CIDR insert branch has no block intro; the bare-IP branch does
 → Add one line that CIDR strings are inserted as given (not rewritten to a host prefix)

## Spec
none

## Security
1. [hard] Fail-open on deny — `pkg/iplookup/iplookup.go` — `0.0.0.0/0` (and `::/0`) mark the shared radix root, so membership is true for the other address family
 → Keep IPv4 and IPv6 on separate roots so prefix 0 stays same-family

## Performance
none

## Applied
- security 1: separate `v4Root` / `v6Root`; tests for catch-all family isolation; catalog spec + usage Gotcha
- standards 1: rename Checker field and `NewChecker` local to `trustedCIDRs`
- standards 2: block intros on `ContainsIP`
- standards 3: CIDR-insert block intro in `NewChecker`

## Recorded and skipped
none.

Standards: 3 findings, worst: Name for the scope at `pkg/ip/ip.go:20`
Spec: 0 findings, worst: none
Security: 1 finding, worst: Fail-open on deny at `pkg/iplookup/iplookup.go`
Performance: 0 findings, worst: none
