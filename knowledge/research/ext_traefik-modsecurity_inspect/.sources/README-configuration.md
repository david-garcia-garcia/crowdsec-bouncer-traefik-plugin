---
url: https://github.com/david-garcia-garcia/traefik-modsecurity/blob/e860d2494f41d49172f2d8aae916615c8ee356e1/README.md
title: README Configuration (inspect knobs)
fetched: 2026-10-12
authority: official
ref: github.com/david-garcia-garcia/traefik-modsecurity@e860d2494f41d49172f2d8aae916615c8ee356e1:README.md
---

failMode default open; close = empty HTTP 502. Allowed open, close.

bypassRules default empty. method case-insensitive, empty = any method. pathRegexp Go RE2 unanchored MatchString against req.URL.Path (percent-decoded, not slash-normalized; not the query). Empty = any path. Plugin does not insert ^ or $. Invalid pathRegexp fails construction. Matching requests get header `bypassrule`. WebSocket handshake GETs are inspected like any other GET.

maxBodySizeBytes YAML example `5242880`. Comment: Default 5242880 (5 MB). Requests exceeding this limit return HTTP 413. Set to 0 for unlimited (not recommended). Conflicts with CreateConfig 8 MiB and Prepare filling 0 — follow source on this pin.

denyVerbsWithBody default HEAD GET DELETE OPTIONS TRACE CONNECT. Listed method with a body → HTTP 400; no ModSecurity; no next; including when WAF already unhealthy. Omitted uses default. Explicit empty list denies nothing. Old keys ignoreBodyForVerbs / ignoreBodyForVerbsDeny are removed.

Header values: ok / blocked (sidecar 3xx/4xx or oversize body) / error / unhealthy / bypassrule.
