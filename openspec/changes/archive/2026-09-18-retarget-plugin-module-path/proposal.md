## Why

This fork still identifies as `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin` to Go, Yaegi, Traefik, and Main CI. Traefik cannot load this tree beside the upstream catalog plugin, so operators who keep maxlerebourg loaded cannot migrate to this fork as a second plugin.

## What Changes

- Retarget `go.mod` `module`, every in-tree import of that module, and `.traefik.yml` `import` to `github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin`. Keep package clause `crowdsec_bouncer_traefik_plugin` (last path segment unchanged; do not add `basePkg`).
- Set `.traefik.yml` `displayName` to `CrowdSec Bouncer Traefik Plugin (david-garcia-garcia)`.
- Point Main CI checkout and working-directory at `go/src/` plus that same `go.mod` module path.
- Flip in-repo runnable compose (root `docker-compose.yml` and `examples/*/docker-compose.yml` that already have commented localPlugins + bind-mount) to `localPlugins` + bind-mount at the new module path. Keep alias `bouncer`. Do not leave a catalog `version=` of this unpublished fork. Do not keep maxlerebourg as the example identity.
- Retarget already-local paths (`docker-compose.local.yml` is already new; `geoenrich-decisions`, real e2e, mock e2e): path only, alias `bouncer` stays.
- Kubernetes values and binary-vm: `localPlugins` + new moduleName; operator must mount/copy sources to `plugins-local/src/<module>`.
- README: working static example is `localPlugins` under alias `bouncer`. Note that catalog GET of this module 404s, the catalog will not list a fork, and operators who keep upstream `experimental.plugins.bouncer` must register this fork under a different alias.
- Rewrite live OpenSpec SHALLs/WHENs that still name the old import. Do not touch `openspec/changes/archive/**`. After apply, usage `core_plugin_middleware.md` “Do not change import” becomes keep import matching `go.mod`.
- **Not BREAKING** for ban/captcha/LAPI behavior. Operators already loading this tree as a local plugin must move the bind-mount and `moduleName` to the new path. Catalog download of this module stays 404 (out of scope to publish).

## Capabilities

### New Capabilities

- `core_plugin_middleware_local-plugin`: This fork’s Traefik load contract — `.traefik.yml` `import` matches `go.mod`, `displayName` distinguishes from upstream, in-tree runnable examples/e2e load via `localPlugins` at that module path and MUST NOT pin a catalog `version=` of this unpublished module.

### Modified Capabilities

- `core_plugin_middleware_bouncer`: Yaegi `WHEN` Traefik loads this plugin names the new module path.
- `build_ci_github_module-path`: Main checkout path equals `go.mod` at the new module.
- `build_ci_github_race-detector`: Race job checkout path equals that same module.

## Impact

- Identity: `go.mod`, `plugin.go`, `pkg/**/*.go` imports, `.traefik.yml`
- CI: `.github/workflows/main.yml`
- Load paths: `docker-compose.yml`, `examples/**`, `tests/e2e/**`
- Live specs listed above
- Docs: `README.md`; usage `knowledge/devdocs/core_plugin_middleware.md` after apply
- Out of scope: `renovate.json`, remotes, catalog publish, `pkg/` directory names, `traefik-middleware-utilities`, `traefik-geoblock`, archive OpenSpec folders
