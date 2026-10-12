---
url: https://github.com/david-garcia-garcia/traefik-modsecurity/blob/e860d2494f41d49172f2d8aae916615c8ee356e1/pkg/modsecurity/body.go
title: body.go
fetched: 2026-10-12
authority: source
ref: github.com/david-garcia-garcia/traefik-modsecurity@e860d2494f41d49172f2d8aae916615c8ee356e1:pkg/modsecurity/body.go
---

`readInboundBody`: if `maxBodySizeBytes > 0`, `req.Body = http.MaxBytesReader(rw, req.Body, p.maxBodySizeBytes)`. Known ContentLength > pool cap uses `io.ReadAll` (no pool). Else pooled copy; chunked/unknown still pools until the pool cap then owns the rest. MaxBytesError is returned to the caller (ServeHTTP maps it to 413).
