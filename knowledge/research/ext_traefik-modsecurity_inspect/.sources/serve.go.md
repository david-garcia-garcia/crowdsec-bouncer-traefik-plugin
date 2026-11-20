---
url: https://github.com/david-garcia-garcia/traefik-modsecurity/blob/e860d2494f41d49172f2d8aae916615c8ee356e1/pkg/modsecurity/serve.go
title: serve.go
fetched: 2026-10-12
authority: source
ref: github.com/david-garcia-garcia/traefik-modsecurity@e860d2494f41d49172f2d8aae916615c8ee356e1:pkg/modsecurity/serve.go
---

Bypass match → token `bypassrule`, `next`, return.

denyVerbsWithBody: MaxBytesReader 1 byte; if a byte is read → Warn + `http.Error` 400 `"HTTP "+method+" requests should not have a body"`, return.

Sidecar URL: `modSecurityUrl + req.URL.RequestURI()`. Header copy: `proxyReq.Header = make(...); for h, val := range req.Header { proxyReq.Header[h] = val }`. Comment: Incoming Host is on req.Host, not in the header map. Traefik already set X-Real-Ip / leftover XFF. Then `proxyReq.Host = req.Host`. No X-Real-IP set, no X-Forwarded-For append.

Status split: `>= 300 && < 500` → blocked + `forwardResponse`. Then discard body. `>= 500` → failure + `serveFailClosedOrNext` (5xx body not copied). Else allow + `next`.

`forwardResponse` / `omitSidecarResponseHeader`: omit Server; Connection, Keep-Alive, Transfer-Encoding, Upgrade, Te, Trailer; names with `proxy-` prefix; names listed in Connection token list.

`replyInboundBodyReadFailure`: `*http.MaxBytesError` → 413 `Request body too large`, token `blocked`. Else empty 502.

`serveFailClosedOrNext`: close → empty 502; else next.
