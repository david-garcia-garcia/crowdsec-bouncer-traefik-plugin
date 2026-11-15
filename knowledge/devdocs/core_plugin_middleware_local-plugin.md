# Local plugin

## Language

**Go module path**:
The `go.mod` `module` string. `.traefik.yml` `import` equals it. Traefik `moduleName`, `plugins-local/src/<module>`, and Main/race checkout `go/src/<module>` reuse it.
_Avoid_: `github.repository` as the identity, a fourth path, upstream `maxlerebourg` as this tree's module

**Local plugin**:
A Traefik `experimental.localPlugins.<alias>` registration: `moduleName` is the Go module path, sources sit at `plugins-local/src/<that path>`, and there is no `version`.
_Avoid_: `version` on a local plugin, a catalog pin in a compose that bind-mounts the checkout

**Catalog plugin**:
A Traefik `experimental.plugins.<alias>` registration: `moduleName` is the Go module path and `version` is a release tag that plugins.traefik.io serves. Traefik downloads it at startup into `plugins-storage`.
_Avoid_: a catalog pin older than `v1.9.0` (not served), `github.com/maxlerebourg/...` as this tree's `moduleName`

**Plugin alias**:
The Traefik routing key (`plugin.<alias>`). In-tree this tree uses `bouncer`.
_Avoid_: `moduleName` as the routing name, a second in-tree middleware family

## Overview

Keep one Go module path. Compose files and e2e harnesses that run from a checkout load this tree as a Local plugin. Install examples that do not ship the tree (Kubernetes, binary VM) and the README use the Catalog plugin: plugins.traefik.io lists this module and serves its release tags from `v1.9.0`. Spec: `core_plugin_middleware_local-plugin`. Yaegi `New`: `core_plugin_middleware.md`.

## How to use

- Set `go.mod` `module` to `github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin`. Rewrite every in-tree import of this module to that path.
- Keep the root package clause `crowdsec_bouncer_traefik_plugin`. Do not set `.traefik.yml` `basePkg`.
- Set `.traefik.yml` `import` equal to the Go module path.
- Set `.traefik.yml` `displayName` to `CrowdSec Bouncer Traefik Plugin (david-garcia-garcia)`. Do not leave it empty. Do not use upstream `Crowdsec Bouncer Traefik Plugin`.
- In compose and e2e that run from a checkout, register `experimental.localPlugins.bouncer` (CLI `experimental.localplugins.bouncer`) with `moduleName` equal to the Go module path, place sources at `plugins-local/src/<that module>` (bind-mount or symlink), and set no `version`.
- In install examples that do not ship the tree (`examples/kubernetes`, `examples/binary-vm`), register `experimental.plugins.bouncer` with the same `moduleName` and a pinned release `version: "vX.Y.Z"`. Renovate bumps that pin.
- Keep routing `plugin.bouncer` in-tree.
- On a host that already has upstream `experimental.plugins.bouncer`, use a different Plugin alias (`plugins.crowdsec` or `localPlugins.crowdsec`, with `plugin.crowdsec`).

## Pattern snippet

```yaml
# install example: catalog release
experimental:
  plugins:
    bouncer:
      moduleName: github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin
      version: "v1.9.6"
```

```yaml
# checkout: local plugin
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
- `tests/e2e/real/config/docker-compose.test.yml`
- `examples/kubernetes/traefik/values.yml`
- `examples/binary-vm/files/traefik/traefik.yml`

## Gotchas

- The catalog serves this module from `v1.9.0`; `v1.8.2` returns 500 and Traefik fails the install on any non-200. An older measurement (404 at `v1.7.1`, 2026-09-18) predates the catalog listing (2026-09-21) and no longer holds. Research: `knowledge/research/ext_traefik_plugins_catalog/notes.md`.
- Same Plugin alias is a map write: local overwrites catalog. Two plugins need two aliases.
- Last path segment is unchanged, so Traefik’s derived `basePkg` stays `crowdsec_bouncer_traefik_plugin`.
- Research extracts may still show dest-era `maxlerebourg` paths; do not copy those into new compose.
