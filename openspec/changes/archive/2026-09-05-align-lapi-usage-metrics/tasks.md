## 1. Cache remediation grammar

- [x] 1.1 Add `RemediationKind` / `RemediationOrigin` / `RemediationWithOrigin` on `pkg/cache` (letter, optional U+001F origin)
- [x] 1.2 Use `RemediationKind` in `IsActiveRemediation`, `PreferRemediation`, and Range index membership

## 2. Metrics on CrowdsecConnection

- [x] 2.1 Stamp `utc_startup_timestamp` in `New`; replace scalar `IncBlocked` with labeled `IncDropped` / `IncProcessed` and stream/alone `active_decisions` gauge
- [x] 2.2 `MetricsOrigin` rewrites `lists` + scenario to `lists:<scenario>`
- [x] 2.3 `reportMetrics` emits `dropped` / `processed` / `active_decisions` windows; drop `labels.type=traefik_plugin`; reset counters after a successful POST
- [x] 2.4 Store origin on Ip/header cache writes (stream and live); return Kind to lookup callers

## 3. Bouncer request path

- [x] 3.1 `ip.Family` from `GetRemoteIP` output
- [x] 3.2 `IncProcessed` for enabled requests (including trusted bypass)
- [x] 3.3 `IncDropped` with origin/ip_type/remediation on ban, captcha, AppSec, and failure paths

## 4. Tests

- [x] 4.1 Unit-test origin rewrite, cache suffix matching, and `reportMetrics` JSON (dropped labels, processed, startup timestamp)
- [x] 4.2 Keep existing decisionscope / bouncer tests passing with Kind-aware matching
