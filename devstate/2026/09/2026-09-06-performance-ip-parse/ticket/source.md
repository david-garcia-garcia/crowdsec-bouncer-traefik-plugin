# Parse the client IP once on the request path and pass net.IP along

Why: ServeHTTP re-parses the same GetRemoteIP string for metrics, trusted-client check, and Range membership. That is re-deriving a fact the hop walk or parseIP already had. Cache keys and logs can keep the string.

Next agent brief:

Goal: After the client address is known, parse it once. Trusted-IP check, Range membership, and usage-metrics ip_type all use that net.IP (family from To4(), not another ParseIP).

Today (allow path, stream, no XFF):

ip.GetRemoteIP (pkg/ip/checker.go) — SplitHostPort on RemoteAddr only. Does not parse the client address.
Bouncer.recordProcessed → ip.Family(remoteIP) (pkg/ip/network.go) — net.ParseIP + To4.
clientPoolStrategy.Checker.Contains(remoteIP) — parseIP again, then ContainsIP.
LookupCachedRemediation → RangeMembership.Remediation(remoteIP) (pkg/decisionscope/rangemembership.go) — ParseIP again, then iplookup.IsContained(parsed).
A ban adds a fifth parse: recordDropped → Family again.

With X-Forwarded-For, PoolStrategy.getIP already Contains (parse) each hop, returns the string, and the three call sites parse that string again.

Checker.ContainsIP(net.IP) and Helper.IsContained(net.IP) already exist. IncProcessed / IncDropped already take an ip_type string; they do not need to parse.

Do:

Parse once at the point the client string is chosen (best: GetRemoteIP / the XFF walk keeps the winning hop’s net.IP; otherwise parse immediately after GetRemoteIP in ServeHTTP).
Trusted-client check: ContainsIP(parsed), not Contains(string).
Range: Remediation (or a sibling) takes net.IP; stop parsing inside RangeMembership.Remediation.
Metrics: family from the parsed IP (To4() != nil → ipv4, else ipv6, empty if parse failed). Pass that string into IncProcessed / IncDropped. Do not call ip.Family(remoteIP) on the request path.
Keep remoteIP string for cache keys, LAPI live lookup, AppSec, logs, ban template ClientIP. Do not thread net.IP through handleBanServeHTTP / handleNextServeHTTP.
Do not:

Only cache the family string in ServeHTTP and leave Contains + Range still parsing (that is the metrics pair only; not the job).
Parse RemoteAddr again on the connection or metrics path.
Change Range-index Redis shape, plugin origin labels, or expand CIDRs to hosts.
Introduce a new address type beside net.IP.
Spec/docs: knowledge/devdocs/core_plugin_ip.md (today: GetRemoteIP then Contains on the string; Family on the string). core_plugin_lapi_usage-metrics.md snippet still shows ip.Family(remoteIP). core_plugin_middleware.md / core_plugin_decisionscope.md if they still say “string then Contains”. Spec core_plugin_lapi_usage-metrics already says ip_type from GetRemoteIP, not from RemoteAddr — behavior unchanged; owner of the parse moves.

Tests: GetRemoteIP still returns the same string. ContainsIP used when ServeHTTP has a parsed IP. Range membership with a net.IP matches today’s string path. Family can stay for decision values / tests; request path must not call it. Existing bouncer + ip + decisionscope tests should stay green without new suites beyond the parse-once wiring.

Out of scope / already done: processed is lock-free (atomic.AddInt64). Fail-closed origins (plugin:tech_*, plugin:lapi_failure, plugin:appsec_failure) stay as they are.

I did not add this to devstate/.../issues.md; that file is the range-index origin leftover. Say if you want it appended there.
