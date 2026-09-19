# Store Range remediation origin on the radix node

Problem: In stream mode with the in-memory DecisionStore, a Range HIT is the only CPU cliff on the request path. RangeMembership.Remediation already has the winning prefixLen from iplookup.Helper.IsContained, then storedMatchingPrefix walks every CIDR in storedByCIDR and net.ParseCIDR + Contains each one to recover the stored letter+origin. Measured (compiled Go): 1k CIDRs ≈ 40µs / 1986 allocs; 10k CIDRs ≈ 450µs / 19623 allocs. A Range miss is already ~26 ns / 0 allocs.

Desired: Put the stored remediation (letter, optional U+001F origin) on the radix endpoint so a Range hit is O(prefix), not O(n) ParseCIDR. Behavior stays the same: ban wins over captcha; origin is the winning CIDR's stored suffix; nil/empty membership is a miss. Do not geolocate. Do not change Redis, live/none hydration, or the range-index blob format unless required to keep request-path lookup correct.

Out of scope: Redis request-path, cache.ErrMiss sentinel, lazy slog, AppSec, ttl_map lock redesign, Yaegi.

Key files: pkg/decisionscope/rangemembership.go (storedMatchingPrefix), pkg/iplookup/iplookup.go, knowledge/devdocs/core_plugin_decisionscope.md, existing zzz_range*_test.go.

Deployment constraint: stream mode + in-memory cache only. Do not add Redis to the design.
