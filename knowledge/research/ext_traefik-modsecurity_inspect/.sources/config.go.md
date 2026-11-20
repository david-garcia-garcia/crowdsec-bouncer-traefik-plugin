---
url: https://github.com/david-garcia-garcia/traefik-modsecurity/blob/e860d2494f41d49172f2d8aae916615c8ee356e1/pkg/modsecurity/config.go
title: config.go
fetched: 2026-10-12
authority: source
ref: github.com/david-garcia-garcia/traefik-modsecurity@e860d2494f41d49172f2d8aae916615c8ee356e1:pkg/modsecurity/config.go
---

BypassRule: Method, PathRegexp. Comment: empty method = every method; empty pathRegexp = every path; RE2 unanchored MatchString on req.URL.Path (percent-decoded, not slash-normalized); plugin does not insert ^ or $.

CreateConfig: MaxBodySizeBytes `8 * 1024 * 1024`, MaxBodySizeBytesForPool `5 * 1024 * 1024`, DenyVerbsWithBody `HEAD GET DELETE OPTIONS TRACE CONNECT`, FailMode `open`.

Prepare: MaxBodySizeBytes `0` → CreateConfig 8MiB (so 0 is not unlimited). DenyVerbsWithBody `nil` → default list; explicit empty keeps empty (deny nothing). failMode empty → open; else must be open|close.
