---
url: https://doc.traefik.io/traefik-hub/api-gateway/guides/plugin-development-guide
title: Plugin Development Guide (Traefik Hub) — constructor, manifest, skeleton
fetched: 2026-09-05
authority: official
---

.traefik.yml import: required; Go import path; must match repository / go.mod / import statements.
basePkg: optional; "Auto-derived from import if not specified".
Plugin Requirements: export Config struct, CreateConfig(), New() creating an http.Handler.
Skeleton New(ctx, next, config *Config, name); CreateConfig() *Config; type Config in the same package as New.
Local-dev directory listing: plugin.go, go.mod, go.sum, .traefik.yml.
