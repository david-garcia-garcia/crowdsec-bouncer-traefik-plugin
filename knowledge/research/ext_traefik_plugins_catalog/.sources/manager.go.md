---
url: https://github.com/traefik/traefik/blob/faa1eb590646aed94e561e24a59be0c47353ae95/pkg/plugins/manager.go
title: pkg/plugins/manager.go
fetched: 2026-09-18
authority: source
ref: github.com/traefik/traefik@faa1eb590646aed94e561e24a59be0c47353ae95:pkg/plugins/manager.go
---

const pluginsURL = "https://plugins.traefik.io/public/"
InstallPlugin downloads (downloader.Download(ctx, plugin.ModuleName, plugin.Version)), optionally checks hash, then unzip.
Download failure wraps as "unable to download plugin %s".
Unzip destination is sources/src/<moduleName> (goPathSrc + FromSlash(moduleName)).
ReadManifest joins goPath, src, moduleName, .traefik.yml.
