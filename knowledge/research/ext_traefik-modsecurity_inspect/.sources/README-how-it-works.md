---
url: https://github.com/david-garcia-garcia/traefik-modsecurity/blob/e860d2494f41d49172f2d8aae916615c8ee356e1/README.md
title: README How it works
fetched: 2026-10-12
authority: official
ref: github.com/david-garcia-garcia/traefik-modsecurity@e860d2494f41d49172f2d8aae916615c8ee356e1:README.md
---

Architecture: plugin sends a copy to the WAF. If allowed, Traefik forwards the original to the application. If blocked, the client gets that block and the app is never called. WAF is inspect-only: after CRS request phases it answers HTTP 200. It does not reverse-proxy to a second site.

How it works:
- 2xx — allow: write `ok` on modSecurityStatusRequestHeader when set, then forward to the real service.
- 3xx / 4xx — security block: copy the sidecar response to the client, omitting hop-by-hop headers (Connection, Keep-Alive, Transfer-Encoding, Upgrade, Proxy-*, Te, Trailer) and Server. Body is whatever page ModSecurity produced. When the header is set, write `blocked`.
- 5xx — WAF failure, not a block: header `error` when configured, count a health-tracker failure when backoff is enabled, then fail-open to next unless failMode close (empty HTTP 502, no next). Sidecar 5xx body is not forwarded.
