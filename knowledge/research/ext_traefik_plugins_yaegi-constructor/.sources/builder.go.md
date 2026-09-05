---
url: https://github.com/traefik/traefik/blob/faa1eb590646aed94e561e24a59be0c47353ae95/pkg/plugins/builder.go
title: pkg/plugins/builder.go
fetched: 2026-09-05
authority: source
ref: github.com/traefik/traefik@faa1eb590646aed94e561e24a59be0c47353ae95:pkg/plugins/builder.go
---

Constructor = func(context.Context, http.Handler) (http.Handler, error).
NewBuilder: for each catalog and local plugin alias, ReadManifest, then for type middleware call newMiddlewareBuilder once and store on middlewareBuilders[pName].
newMiddlewareBuilder (yaegi/empty runtime): newInterpreter then newYaegiMiddlewareBuilder(i, manifest.BasePkg, manifest.Import).
Build(pName, config, middlewareName): descriptor.newMiddleware(config, middlewareName) then return m.NewHandler. This is the Constructor later invoked with (ctx, next).
