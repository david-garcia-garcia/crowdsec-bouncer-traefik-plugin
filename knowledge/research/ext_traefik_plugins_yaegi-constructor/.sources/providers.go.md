---
url: https://github.com/traefik/traefik/blob/faa1eb590646aed94e561e24a59be0c47353ae95/pkg/plugins/providers.go
title: pkg/plugins/providers.go
fetched: 2026-09-05
authority: source
ref: github.com/traefik/traefik@faa1eb590646aed94e561e24a59be0c47353ae95:pkg/plugins/providers.go
---

Provider basePkg default is the same hyphen-to-underscore of path.Base(Import).
Generated Yaegi wrapper: func NewWrapper(ctx, config *basePkg.Config, name) (plugins.PP, error) { return basePkg.New(ctx, config, name) }.
Middleware loader does not generate this wrapper; provider plugins need a type named Config in basePkg. This product is type middleware.
