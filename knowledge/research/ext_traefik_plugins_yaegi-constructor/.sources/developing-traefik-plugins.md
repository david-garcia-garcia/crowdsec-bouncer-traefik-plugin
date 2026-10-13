---
url: https://plugins.traefik.io/create
title: Developing Traefik Plugins
fetched: 2026-09-05
authority: official
---

Yaegi plugins are developed in Go. A Traefik plugin is essentially a Go package, executed on the fly by Yaegi embedded in Traefik.
Required skeleton: Middleware Demo Plugin (github.com/traefik/plugindemo).
Catalog needs .traefik.yml at repo root with valid testData, valid go.mod, git tags; dependencies must be vendored.
