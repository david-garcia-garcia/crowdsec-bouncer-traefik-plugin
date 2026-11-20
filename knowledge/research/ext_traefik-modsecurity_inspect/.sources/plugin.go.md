---
url: https://github.com/david-garcia-garcia/traefik-modsecurity/blob/e860d2494f41d49172f2d8aae916615c8ee356e1/pkg/modsecurity/plugin.go
title: plugin.go (CheckRedirect)
fetched: 2026-10-12
authority: source
ref: github.com/david-garcia-garcia/traefik-modsecurity@e860d2494f41d49172f2d8aae916615c8ee356e1:pkg/modsecurity/plugin.go
---

HTTP client CheckRedirect returns `http.ErrUseLastResponse`. Comment: Keep the sidecar's own 3xx so ServeHTTP can copy it; default follow hides redirect blocks.

failMode stored from prepared `cfg.FailMode`. denyVerbsWithBody stored via `createMethodSet` (uppercase). compiledBypass from `compileBypassByMethod`.
