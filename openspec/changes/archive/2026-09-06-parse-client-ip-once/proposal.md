## Why

ServeHTTP re-parses the same GetRemoteIP string for usage-metrics `ip_type`, trusted-client membership, and Range membership. That reconstructs a fact the hop walk or `parseIP` already had. Cache keys and logs can keep the string.

## What Changes

- `GetRemoteIP` keeps the chosen client address as `net.IP` (XFF walk retains the winning hop’s parse; RemoteAddr fallback parses after `SplitHostPort`). The returned string stays the same.
- Trusted-client check uses `ContainsIP` on that `net.IP`, not `Contains` on the string. An unparseable chosen address still fail-closes as trusted-IP checker failure (`plugin:tech_trustipfail`).
- Stream/alone Range membership takes that `net.IP`; `RangeMembership.Remediation` MUST NOT parse the string.
- Request-path `ip_type` comes from that `net.IP` (`To4()` → ipv4/ipv6, empty if nil). `IncProcessed` / `IncDropped` receive that string. The request path MUST NOT call `ip.Family(remoteIP)`.
- Usage packets `core_plugin_ip`, `core_plugin_lapi_usage-metrics`, and `core_plugin_decisionscope` match that wiring.
- **Not BREAKING.** No public Traefik config keys. No new address type. Range-index Redis shape and plugin origin labels stay as they are.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_ip_radix-lookup`: GetRemoteIP also yields the chosen address as `net.IP`; trusted-client membership uses `ContainsIP` on that value.
- `core_plugin_decisions_scopes`: Range request lookup classifies that `net.IP`; it MUST NOT parse the client string again.
- `core_plugin_lapi_usage-metrics`: request-path `ip_type` comes from `To4()` of that `net.IP`, not `Family` of the string and not `RemoteAddr`.

## Impact

- `pkg/ip/checker.go` (`GetRemoteIP`, XFF walk)
- `pkg/bouncer/bouncer.go` (`ServeHTTP`, `recordProcessed`, `recordDropped`, handlers that count drops)
- `pkg/decisionscope/rangemembership.go`, `pkg/decisionscope/lookup.go`
- Existing tests in `pkg/ip`, `pkg/bouncer`, `pkg/decisionscope` (signature wiring)
- `knowledge/devdocs/core_plugin_ip.md`, `core_plugin_lapi_usage-metrics.md`, `core_plugin_decisionscope.md`
