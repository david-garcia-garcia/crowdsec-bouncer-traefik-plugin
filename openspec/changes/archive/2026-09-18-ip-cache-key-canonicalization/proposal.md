## Why

Two defects, both in how `pkg/decisionscope` keys the shared decision cache.

**Ip cache keys are asymmetric.** CrowdSec stores a decision value exactly as it was submitted and
never canonicalizes it (measured against `crowdsecurity/crowdsec:v1.8.0`: the stream hands back
`2001:0db8:0000:0000:0000:0000:0000:0001`, `2001:DB8::2`, and `::ffff:192.0.2.4` verbatim). On
DestBranch `IPCacheKey` canonicalizes only when `net.ParseCIDR` succeeds on a host prefix, so a bare
value is stored under whatever spelling arrived, and the request path keys on the raw client address
text. A ban stored under one spelling of an address is invisible to a request that spells it another
way. LAPI itself needs no workaround: the same experiment showed `?ip=` matches numerically, so the
whole defect is inside this plugin's string-keyed cache.

**The range-index apply can wipe the shared index.** `readRangeIndex` collapses every cache error to
`""`, so a read that did not answer is indistinguishable from an index that is genuinely empty.
`ApplyRangeBatch` then rebuilds from that empty base and writes back only the CIDRs this one poll
carried — or, on a removal-only tick, deletes the shared key. Every other bouncer's Range ban is
dropped until a `startup=true` resync. This needs no timing window: `Get` runs on a round-robin
**read replica** while `Acquire` and `Set` run on the **writer**, so one dead entry in
`redisCacheReadHosts` reaches it on a completely healthy writer.

## What Changes

- **Deliverable 1.** `IPCacheKey` collapses any value that parses as an address to `net.IP.String()`;
  a value that parses as neither a host prefix nor an address is still keyed verbatim. The new
  `IPLookupCacheKey(remoteIP, ipAddr)` is the request-path entry point to that same rule, reusing the
  `net.IP` `pkg/ip.GetRemoteIP` already parsed instead of parsing the string twice.
  `LookupCachedRemediation` and `LookupCacheKeys` use it. **The write side moves in the same commit**:
  the stream store and delete paths inherit the new `IPCacheKey`, and `handleNoStreamCache` writes the
  live-mode memo under `IPCacheKey(remoteIP)` instead of the verbatim header text. Canonicalizing only
  the read side was measured to regress live-mode caching into a permanent miss.
- **Deliverable 2.** `readRangeIndex` returns `(string, error)`: `CacheMiss` is an empty index and no
  error, every other failure propagates. `ApplyRangeBatch` returns that error and writes nothing.
  `fetchAndApplyStreamDecisions` returns it too, so the poll is reported as failed — that releases the
  stream lease for an immediate retry and leaves `isCrowdsecStreamStartup` set, so the retry asks for
  the full decision set instead of silently losing this tick's Range delta.
- **Not BREAKING.** No new configuration key. No cache migration: entries written under the old
  spelling expire by TTL, and both spellings of an IPv4 address were already identical.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_decisions_scopes`: the Ip cache key is the canonical spelling of the address on both
  the store side and the request side; the range-index apply MUST NOT write from an index it could
  not read.

## Impact

- `pkg/decisionscope/scope.go`, `lookup.go`, `range.go`
- `pkg/lapi/client_live.go`, `pkg/lapi/client_stream.go`
- Tests: new `pkg/lapi/zzz_ipcachekey_test.go`; `pkg/decisionscope/zzz_scope_test.go`,
  `zzz_range_test.go`, `pkg/lapi/zzz_leaseredis_test.go` (the RESP stand-in learns `DEL`)
- **Behavior change:** a stream poll whose Range apply cannot read the shared index now counts as a
  failed poll. With the default `updateMaxFailure: 0` that marks the stream unhealthy, so cache
  misses take `crowdsecLapiFailureAction` until a poll succeeds. That is the same posture the
  surrounding code already takes for a failed stream fetch, and it is the price of not silently
  dropping the delta.
- Out of scope: non-IP scopes (Country and AS are not addresses and keep `NormalizeHeaderScopeValue`);
  Range decisions, which are served by the range index and not by exact-key lookups; any new
  configuration knob; `pkg/ip`, `pkg/cache`, `pkg/captcha`, `pkg/appsec`; merging, closing, or
  commenting on #34.
