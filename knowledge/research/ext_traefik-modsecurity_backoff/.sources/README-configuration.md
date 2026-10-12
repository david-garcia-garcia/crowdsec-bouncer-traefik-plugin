---
url: https://github.com/david-garcia-garcia/traefik-modsecurity/blob/e860d2494f41d49172f2d8aae916615c8ee356e1/README.md
title: README Configuration (backoff and failMode)
fetched: 2026-10-12
authority: official
ref: github.com/david-garcia-garcia/traefik-modsecurity@e860d2494f41d49172f2d8aae916615c8ee356e1:README.md
---

failMode default `open` (call next). `close`: empty HTTP 502; do not call next. Allowed `open`, `close` (case-insensitive). Applies to sidecar transport errors (not inbound cancel), sidecar 5xx, and the already-unhealthy skip after WAF backoff trips. Omitting the field stays fail-open.

unhealthyWafBackOffPeriodSecs default `0` (gate unused; each WAF failure still follows failMode). Set to 30+ so later requests skip the sidecar for that backoff after threshold. After cooldown the next request is one probe; other in-flight requests stay skipped. Omitted unhealthyWafFailureThreshold defaults to 5. Omitted unhealthyWafFailureWindowSecs defaults to 10 (kept for reclaim hash; unused by the gate). Omitted unhealthyWafFailureRatio uses the packaged 0.30 credit refill. Omitted unhealthyWafMaxBackOffPeriodSecs equals unhealthyWafBackOffPeriodSecs (fixed cooldown). Set unhealthyWafFailureThreshold: 1 to trip on the first sidecar error.

denyVerbsWithBody: when a listed method has a body, HTTP 400; does not call ModSecurity or next, including when the WAF is already unhealthy.
