---
url: https://github.com/traefik/traefik/blob/faa1eb590646aed94e561e24a59be0c47353ae95/pkg/server/middleware/plugins.go
title: pkg/server/middleware/plugins.go
fetched: 2026-09-05
authority: source
ref: github.com/traefik/traefik@faa1eb590646aed94e561e24a59be0c47353ae95:pkg/server/middleware/plugins.go
---

newTraceablePlugin(ctx, name, plug plugins.Constructor, next): h, err := plug(ctx, next). That call is YaegiMiddleware.NewHandler, which calls the plugin New.
findPluginConfig: rawConfig map must have length 1; that key is the plugin type (static alias).
