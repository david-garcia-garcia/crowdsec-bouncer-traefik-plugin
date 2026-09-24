---
url: https://github.com/david-garcia-garcia/traefik-middleware-utilities/blob/42e6a1a967155318023c4defe491d1d423e165b6/traefikemulator/emulator.go
title: traefikemulator/emulator.go
fetched: 2026-09-24
authority: source
ref: github.com/david-garcia-garcia/traefik-middleware-utilities@42e6a1a967155318023c4defe491d1d423e165b6:traefikemulator/emulator.go
---

Package constructs one Traefik configuration generation at a time.

Exported: Constructor, Route, Emulator, New, Apply, Stop, Handler, Serve.

Apply cancels the previous generation, then constructs routes in order on one context. A constructor error omits that route and leaves the generation context live. Duplicate Route.Name records a failure and skips that row.

Empty MiddlewareName uses Name.

git blob SHA: 3e023e0931700cddef3d6ee8450119c54ae291f1
