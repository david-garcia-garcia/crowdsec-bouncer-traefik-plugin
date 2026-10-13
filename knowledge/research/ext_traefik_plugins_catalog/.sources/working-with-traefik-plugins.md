---
url: https://plugins.traefik.io/install
title: Working with Traefik Plugins
fetched: 2026-09-18
authority: official
---

Catalog UI Install Plugin emits the static-config snippet. Plugins load only at startup; a load error disables the plugin.
Example static config registers two catalog plugins under two aliases (block + rewrite) with distinct moduleName and version.
Local mode: private or in-development plugins. Sources under ./plugins-local/src/<module> instead of download.
