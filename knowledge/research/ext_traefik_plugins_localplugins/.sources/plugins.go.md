---
url: https://github.com/traefik/traefik/blob/faa1eb590646aed94e561e24a59be0c47353ae95/pkg/plugins/plugins.go
title: pkg/plugins/plugins.go
fetched: 2026-09-05
authority: source
ref: github.com/traefik/traefik@faa1eb590646aed94e561e24a59be0c47353ae95:pkg/plugins/plugins.go
---

const localGoPath = "./plugins-local/"
SetupRemotePlugins installs catalog plugins (moduleName + version) via manager.InstallPlugin.
SetupLocalPlugins reads each LocalDescriptor.ModuleName and calls checkLocalPluginManifest.
checkLocalPluginManifest calls ReadManifest(localGoPath, descriptor.ModuleName).
Local plugins have no version in this file; remote plugins require Version != "".
