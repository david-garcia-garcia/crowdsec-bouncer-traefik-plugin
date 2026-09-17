---
url: https://github.com/traefik/traefik/blob/faa1eb590646aed94e561e24a59be0c47353ae95/pkg/plugins/plugins.go
title: pkg/plugins/plugins.go (Yaegi import checks)
fetched: 2026-09-05
authority: source
ref: github.com/traefik/traefik@faa1eb590646aed94e561e24a59be0c47353ae95:pkg/plugins/plugins.go
---

checkLocalPluginManifest for IsYaegiPlugin: Import must be non-empty; Import must have prefix descriptor.ModuleName ("the import %q must be related to the module name %q").
Also requires DisplayName, Summary, TestData != nil, and type middleware|provider with allowed runtime.
