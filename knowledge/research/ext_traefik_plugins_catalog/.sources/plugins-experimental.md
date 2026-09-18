---
url: https://doc.traefik.io/traefik/v3.7/reference/install-configuration/experimental/plugins/
title: Traefik Plugins Experimental Configuration (v3.7)
fetched: 2026-09-18
authority: official
---

Catalog: experimental.plugins.<plugin-name>.moduleName and version are required.
plugin-name is the name used in the routing configuration.
CLI: --experimental.plugins.plugin-name.modulename=… and --experimental.plugins.plugin-name.version=vX.XX.X.

Local: experimental.localPlugins.<plugin-name>.moduleName only (no version).
CLI: --experimental.localplugins.plugin-name.modulename=github.com/github-organization/github-repository
Local plugins are for a local directory without publishing to the catalog.
displayName is not a static-config field; it lives on the plugin manifest.
