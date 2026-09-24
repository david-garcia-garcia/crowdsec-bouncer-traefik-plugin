---
url: https://github.com/david-garcia-garcia/traefik-middleware-utilities/blob/42e6a1a967155318023c4defe491d1d423e165b6/traefikemulator/emulator_test.go
title: traefikemulator/emulator_test.go
fetched: 2026-09-24
authority: source
ref: github.com/david-garcia-garcia/traefik-middleware-utilities@42e6a1a967155318023c4defe491d1d423e165b6:traefikemulator/emulator_test.go
---

Tests: New(nil) panics; Apply cancels previous generation before next New; routes share one context; omitted route is not constructed; failed New is absent and sibling stays; Serve hits current generation only; shared middleware name constructs twice; duplicate route name in one Apply; Handler/Serve missing route; Handler/Serve after Stop; Stop cancels last generation; empty Apply leaves no servable routes.
