---
url: https://github.com/david-garcia-garcia/traefik-modsecurity/blob/e860d2494f41d49172f2d8aae916615c8ee356e1/pkg/modsecurity/bypass.go
title: bypass.go
fetched: 2026-10-12
authority: source
ref: github.com/david-garcia-garcia/traefik-modsecurity@e860d2494f41d49172f2d8aae916615c8ee356e1:pkg/modsecurity/bypass.go
---

`bypassStatusToken = "bypassrule"`. `compileBypassByMethod`: invalid PathRegexp → `invalid bypass rule pathRegexp %q`. Empty method+path → match-all. `match`: uppercase method map lookup else anyMethod; `req.URL.Path`; unanchored `MatchString`. Nil req → false. Empty rules → compiledBypass{} (match always false).
