---
url: https://github.com/traefik/traefik/blob/faa1eb590646aed94e561e24a59be0c47353ae95/pkg/plugins/manager.go
title: pkg/plugins/manager.go
fetched: 2026-09-05
authority: source
ref: github.com/traefik/traefik@faa1eb590646aed94e561e24a59be0c47353ae95:pkg/plugins/manager.go
---

const goPathSrc = "src"
const pluginManifest = ".traefik.yml"
ReadManifest(goPath, moduleName) opens filepath.Join(goPath, goPathSrc, filepath.FromSlash(moduleName), pluginManifest).
For local plugins, goPath is "./plugins-local/", so the manifest is ./plugins-local/src/<module>/.traefik.yml.
Catalog InstallPlugin downloads then unzips into sources/src/<module>.
