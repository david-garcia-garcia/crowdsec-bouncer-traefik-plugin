---
url: https://plugins.traefik.io/create
title: Developing Traefik Plugins
fetched: 2026-09-18
authority: official
---

The Plugin Catalog polls GitHub once a day for repositories that match plugin criteria.
Sources come from a Go module proxy; plugins need a git tag.

Checklist for a successful catalog import:
- The repository is not a fork: forks are not added to the catalog.
- The traefik-plugin topic must be set.
- A root .traefik.yml with a valid testData property.
- A valid root go.mod.
- Versioned with a git tag.
- Dependencies vendored in the GitHub repository.

Removing a plugin from the catalog (issue on traefik/piceus) only removes the listing. Go plugin code stays on Go proxies.
