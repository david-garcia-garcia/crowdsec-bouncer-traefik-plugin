---
url: https://doc.traefik.io/traefik/v3.7/reference/install-configuration/experimental/plugins/
title: Traefik Plugins Experimental Configuration (v3.7)
fetched: 2026-09-05
authority: official
---

Catalog plugins: experimental.plugins.<plugin-name>.moduleName and version are required.
CLI: --experimental.plugins.plugin-name.modulename=… and --experimental.plugins.plugin-name.version=vX.XX.X.

Local plugins: experimental.localPlugins.<plugin-name>.moduleName only (no version).
CLI: --experimental.localplugins.plugin-name.modulename=github.com/github-organization/github-repository
The plugin-name is the name used in routing configuration.
localPlugins moduleName is required. No version field on Local Plugin Options.
