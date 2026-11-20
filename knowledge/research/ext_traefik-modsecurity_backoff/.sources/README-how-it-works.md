---
url: https://github.com/david-garcia-garcia/traefik-modsecurity/blob/e860d2494f41d49172f2d8aae916615c8ee356e1/README.md
title: README How it works (5xx trips health)
fetched: 2026-10-12
authority: official
ref: github.com/david-garcia-garcia/traefik-modsecurity@e860d2494f41d49172f2d8aae916615c8ee356e1:README.md
---

5xx — WAF failure, not a block: set modSecurityStatusRequestHeader to `error` when configured, count a health-tracker failure when backoff is enabled, then fail-open to `next` unless `failMode: close` (empty HTTP 502, no `next`). The sidecar 5xx body is not forwarded.

Status token `unhealthy` when ModSecurity is down and backoff is already tripped (README Configuration header-values list).
