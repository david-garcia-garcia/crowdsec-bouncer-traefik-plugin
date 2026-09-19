# Local plugin

## Language

**Go module path**:
The `go.mod` `module` string. `.traefik.yml` `import` equals it. Traefik `moduleName`, `plugins-local/src/<module>`, and Main/race checkout `go/src/<module>` reuse it.
_Avoid_: `github.repository` as the identity, a fourth path, upstream `maxlerebourg` as this tree's module

**Local plugin**:
A Traefik `experimental.localPlugins.<alias>` registration: `moduleName` is the Go module path, sources sit at `plugins-local/src/<that path>`, and there is no `version`.
_Avoid_: catalog plugin, `experimental.plugins` plus `version`

**Plugin alias**:
The Traefik routing key (`plugin.<alias>`). In-tree this tree uses `bouncer`.
_Avoid_: `moduleName` as the routing name, a second in-tree middleware family

## Overview

This unpublished fork is loaded as a Local plugin. Keep one Go module path. Catalog download of this module 404s and plugins.traefik.io does not list forks. Spec: `core_plugin_middleware_local-plugin`. Yaegi `New`: `core_plugin_middleware.md`.

## How to use

- Set `go.mod` `module` to `github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin`. Rewrite every in-tree import of this module to that path.
- Keep the root package clause `crowdsec_bouncer_traefik_plugin`. Do not set `.traefik.yml` `basePkg`.
- Set `.traefik.yml` `import` equal to the Go module path.
- Set `.traefik.yml` `displayName` to `CrowdSec Bouncer Traefik Plugin (david-garcia-garcia)`. Do not leave it empty. Do not use upstream `Crowdsec Bouncer Traefik Plugin`.
- Register in-tree Traefik as `experimental.localPlugins.bouncer` (CLI `experimental.localplugins.bouncer`) with `moduleName` equal to the Go module path.
- Place sources at `plugins-local/src/<that module>` (bind-mount, symlink, or operator copy).
- Keep routing `plugin.bouncer` in-tree.
- Do not set `experimental.plugins.bouncer.version` for this module.
- On a host that already has upstream `experimental.plugins.bouncer`, use a different Plugin alias (`localPlugins.crowdsec` + `plugin.crowdsec`).

## Pattern snippet

```yaml
experimental:
  localPlugins:
    bouncer:
      moduleName: github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin
```

```yaml
# compose bind-mount (repo root → Traefik local GOPATH)
# ./:/plugins-local/src/github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin
# CLI: --experimental.localplugins.bouncer.modulename=github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin
```

## Key files

- `go.mod`
- `.traefik.yml`
- `docker-compose.yml`
- `README.md`
- `tests/e2e/mock/lib/traefik.yml`
- `tests/e2e/real/docker-compose.test.yml`

## Gotchas

- Catalog `GET` of this module at `v1.7.1` or `vX.Y.Z` returns 404. Do not ship a catalog `version=` of this fork as the working install.
- Same Plugin alias is a map write: local overwrites catalog. Two plugins need two aliases.
- Last path segment is unchanged, so Traefik’s derived `basePkg` stays `crowdsec_bouncer_traefik_plugin`.
- Research extracts may still show dest-era `maxlerebourg` paths; do not copy those into new compose.
