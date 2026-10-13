---
url: https://github.com/traefik/traefik/blob/faa1eb590646aed94e561e24a59be0c47353ae95/pkg/plugins/builder.go
title: pkg/plugins/builder.go
fetched: 2026-09-18
authority: source
ref: github.com/traefik/traefik@faa1eb590646aed94e561e24a59be0c47353ae95:pkg/plugins/builder.go
---

NewBuilder(manager, plugins, localPlugins):
1. Range catalog plugins; middlewareBuilders[pName] = builder.
2. Range localPlugins; middlewareBuilders[pName] = builder.

Same alias key: the local write replaces the catalog builder. No error.
Build(pName) looks up middlewareBuilders[pName] only (the routing alias).
