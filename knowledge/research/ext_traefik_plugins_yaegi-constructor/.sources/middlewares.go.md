---
url: https://github.com/traefik/traefik/blob/faa1eb590646aed94e561e24a59be0c47353ae95/pkg/server/middleware/middlewares.go
title: pkg/server/middleware/middlewares.go
fetched: 2026-09-05
authority: source
ref: github.com/traefik/traefik@faa1eb590646aed94e561e24a59be0c47353ae95:pkg/server/middleware/middlewares.go
---

BuildMiddlewareChain(ctx, middlewares []string): alice.New(); for each name, Append a constructor that GetQualifiedName, buildConstructor, then constructor(next).
Plugin branch of buildConstructor: findPluginConfig (exactly one plugin type key); pluginBuilder.Build(pluginType, rawPluginConfig, middlewareName); alice constructor = newTraceablePlugin(ctx, middlewareName, plug, next).
No cache of built plugin handlers keyed by middleware name in this file.
