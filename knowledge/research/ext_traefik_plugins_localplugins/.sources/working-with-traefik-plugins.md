---
url: https://plugins.traefik.io/install
title: Working with Traefik Plugins
fetched: 2026-09-05
authority: official
---

Plugins are loaded dynamically and executed by an embedded interpreter (not compiled into Traefik).
Plugins are parsed and loaded exclusively during startup. Restart required to add or modify a plugin.

Local mode is for private plugins not hosted on GitHub and for testing during development.
Static config must define the module name. Plugins must be placed in ./plugins-local in the working directory of the Traefik process.
Layout: ./plugins-local/src/<module path>/ (example github.com/traefik/plugindemo).
Config: experimental.localPlugins.<alias>.modulename = <module>.
The example plugin is loaded from ./plugins-local/src/github.com/traefik/plugindemo instead of being downloaded.
