---
url: https://github.com/traefik/traefik/blob/faa1eb590646aed94e561e24a59be0c47353ae95/pkg/plugins/plugins.go
title: pkg/plugins/plugins.go
fetched: 2026-09-18
authority: source
ref: github.com/traefik/traefik@faa1eb590646aed94e561e24a59be0c47353ae95:pkg/plugins/plugins.go
---

SetupRemotePlugins(manager, plugins map[string]Descriptor): log "Installing plugin: %s: %s@%s" with alias, moduleName, version; InstallPlugin per entry; fail resets all.
checkRemotePluginsConfiguration: module.CheckPath(moduleName); Version != ""; only one version of a given moduleName (duplicate moduleName error).
SetupLocalPlugins: same duplicate-moduleName rule inside the local map; empty moduleName error.
checkLocalPluginManifest: Yaegi import required; import must have prefix moduleName; DisplayName, Summary, TestData required (empty DisplayName is an error).
localGoPath = "./plugins-local/"
