# Requirement
IssueKey: 2026-09-06-performance-ip-parse

## Problem
`ServeHTTP` re-parses the same client address string for usage-metrics `ip_type`, trusted-client membership, and Range membership. The hop walk or `parseIP` already had that `net.IP`. Cache keys and logs can keep the string.

## Current (code)
- `pkg/ip/checker.go` `GetRemoteIP`: walks XFF via `PoolStrategy.getIP` (each hop `Checker.Contains` → `parseIP`) or `net.SplitHostPort(req.RemoteAddr)`. Returns the client string only; does not return `net.IP`.
- `pkg/bouncer/bouncer.go` `ServeHTTP`: `recordProcessed(remoteIP)` → `ip.Family(remoteIP)` (`pkg/ip/network.go`: `net.ParseIP` + `To4`).
- Same handler: `clientPoolStrategy.Checker.Contains(remoteIP)` → `parseIP` then `ContainsIP`.
- Stream/alone cache hit: `decisionscope.LookupCachedRemediation` → `RangeMembership.Remediation(remoteIP)` (`pkg/decisionscope/rangemembership.go`: `net.ParseIP` then `iplookup.IsContained`).
- Ban/captcha drop: `recordDropped` → `ip.Family(remoteIP)` again.
- `Checker.ContainsIP(net.IP)` and `iplookup.Helper.IsContained(net.IP)` already exist. `IncProcessed` / `IncDropped` already take `ip_type` string (`pkg/crowdsecconnection/connection_metrics.go`).
- Docs: `knowledge/devdocs/core_plugin_ip.md` says GetRemoteIP then `Contains` on the string and `Family` on the string. `knowledge/devdocs/core_plugin_lapi_usage-metrics.md` snippet uses `ip.Family(remoteIP)`. `knowledge/devdocs/core_plugin_decisionscope.md` snippet same. `knowledge/devdocs/core_plugin_middleware.md` says GetRemoteIP, not “string then Contains”.
- Spec `openspec/specs/core_plugin_lapi_usage-metrics/spec.md`: `ip_type` from GetRemoteIP, MUST NOT parse `RemoteAddr` again. Behavior unchanged; owner of the parse moves.

## Desired
- Parse the chosen client address once (prefer: GetRemoteIP / XFF walk keeps the winning hop’s `net.IP`; else parse immediately after GetRemoteIP in ServeHTTP).
- Trusted-client check: `ContainsIP(parsed)`, not `Contains(string)`.
- Range: `Remediation` (or a sibling) takes `net.IP`; stop parsing inside `RangeMembership.Remediation`.
- Metrics: family from that `net.IP` (`To4() != nil` → ipv4, else ipv6, empty if parse failed). Pass into `IncProcessed` / `IncDropped`. Do not call `ip.Family(remoteIP)` on the request path.
- Keep `remoteIP` string for cache keys, LAPI live lookup, AppSec, logs, ban template `ClientIP`. Do not thread `net.IP` through `handleBanServeHTTP` / `handleNextServeHTTP`.
- `GetRemoteIP` still returns the same string. `Family` may stay for decision values / tests.
- Update the usage packets named above. Existing bouncer + ip + decisionscope tests stay green; no new suites beyond parse-once wiring.

## Affected
- `pkg/ip/checker.go` (`GetRemoteIP` / XFF walk)
- `pkg/bouncer/bouncer.go` (`ServeHTTP`, `recordProcessed`, `recordDropped`)
- `pkg/decisionscope/rangemembership.go` (`Remediation`)
- `pkg/decisionscope/lookup.go` (`LookupCachedRemediation` Range call)
- `knowledge/devdocs/core_plugin_ip.md`
- `knowledge/devdocs/core_plugin_lapi_usage-metrics.md`
- `knowledge/devdocs/core_plugin_decisionscope.md` (snippet `ip.Family`)
- Tests next to those packages if signatures change

## Out of scope
- Caching only the family string in ServeHTTP while Contains + Range still parse
- Parsing `RemoteAddr` again on the connection or metrics path
- Range-index Redis shape, plugin origin labels, expanding CIDRs to hosts
- A new address type beside `net.IP`
- Threading `net.IP` through ban/next handlers
- Changing fail-closed origins (`plugin:tech_*`, `plugin:lapi_failure`, `plugin:appsec_failure`)
- Lock-free `processed` (`atomic.AddInt64`) — already done
- Appending this ticket onto `2026-09-05-performance-ip-range` `issues.md`

## Unknowns
- Exact GetRemoteIP signature: return `(string, net.IP, error)` vs parse after GetRemoteIP in ServeHTTP.
- Whether `RangeMembership.Remediation` is renamed/overloaded or a sibling takes `net.IP` and the string method remains for tests.

## Tensions
- None. Ticket matches current code. Previous range-index `issues.md` is a leftover on another run; this is a new IssueKey.
