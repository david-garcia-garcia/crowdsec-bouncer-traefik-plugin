## 1. GetRemoteIP keeps net.IP

- [ ] 1.1 `GetRemoteIP` returns `(string, net.IP, error)`; XFF walk parses each hop once and keeps the winning hop’s `net.IP`; RemoteAddr fallback parses after `SplitHostPort`
- [ ] 1.2 Existing `TestGetRemoteIP` still asserts the same strings (and RemoteAddr-without-port error)

## 2. ServeHTTP wiring

- [ ] 2.1 After GetRemoteIP, compute `ipType` from the parsed IP (`To4()`); `recordProcessed` / `recordDropped` take `ipType` string; do not call `ip.Family(remoteIP)` on the request path
- [ ] 2.2 Nil parsed after successful GetRemoteIP fail-closes with `OriginPluginTechTrustIPFail`; otherwise `ContainsIP(parsed)`
- [ ] 2.3 Pass parsed IP into `LookupCachedRemediation` for Range membership; keep `remoteIP` string for cache keys, live lookup, AppSec, logs, `ClientIP`
- [ ] 2.4 Thread `ipType` (not `net.IP`) through handlers that call `recordDropped`

## 3. Range membership

- [ ] 3.1 `RangeMembership.Remediation` takes `net.IP`; stop parsing inside it
- [ ] 3.2 Existing rangemembership / lookup / connection_range tests parse then call `Remediation`; membership with a `net.IP` matches today’s string path

## 4. Docs

- [ ] 4.1 Update `knowledge/devdocs/core_plugin_ip.md` (GetRemoteIP yields net.IP; ContainsIP on the request path; Family not on the request path)
- [ ] 4.2 Update `knowledge/devdocs/core_plugin_lapi_usage-metrics.md` snippet (ipType from parsed IP, not `ip.Family(remoteIP)`)
- [ ] 4.3 Update `knowledge/devdocs/core_plugin_decisionscope.md` lookup snippet if it still shows `ip.Family(remoteIP)`

## 5. Verify

- [ ] 5.1 `go test ./pkg/ip/ ./pkg/bouncer/ ./pkg/decisionscope/ ./pkg/crowdsecconnection/`
