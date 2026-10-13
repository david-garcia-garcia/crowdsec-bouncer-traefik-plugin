## Context

See proposal.md for motivation. DestBranch is split: `README.md` static `moduleName` and `docker-compose.local.yml` already use `github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin`; `go.mod`, `.traefik.yml` `import`, Main GOPATH, e2e bind-mounts, and most examples still use maxlerebourg.

Traefik constraints (research `ext_traefik_plugins_catalog/`, `ext_traefik_plugins_localplugins/`, `ext_traefik_plugins_yaegi-constructor/`):

- `manifest.import` must be a prefix of Traefik `moduleName` and must match `go.mod` for Yaegi.
- Empty `displayName` is a manifest error. `basePkg` defaults to `path.Base(import)` with `-` → `_` (last segment `crowdsec-bouncer-traefik-plugin` → `crowdsec_bouncer_traefik_plugin`).
- Catalog download is `{pluginsURL}download/{moduleName}/{version}`. Measured 2026-09-18: this fork’s module `@v1.7.1` and `@vX.Y.Z` → 404. Catalog create checklist: forks are not added.
- Same Traefik alias is a map write: local overwrites catalog. Two plugins need two aliases.

Identity owner (explore): `go.mod` `module`. Import and CI checkout reuse that path. Do not invent a fourth string.

## Goals / Non-Goals

**Goals:**

- One Go/Yaegi/Traefik module path for this tree, derived from `go.mod`.
- In-tree runnable loads work after the retarget (localPlugins + bind-mount).
- Live specs that SHALL the old import name the new module.

**Non-Goals:**

- Catalog listing or a second in-tree middleware family.
- Changing `New` lifetime, reclaim, ban/captcha/LAPI behavior, `pkg/` directory names.
- Rewriting `openspec/changes/archive/**` or research extracts that cite dest-era paths.
- Moving `renovate.json` `depNameTemplate` (debt already noted).

## Decisions

1. **`go.mod` is the only identity source.** Set `module` to `github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin`. Rewrite every import of that module (including `.golangci.yml` depguard allow). Set `.traefik.yml` `import` to the same string. Main and race jobs check out and `working-directory` at `go/src/` plus that module. Alternative: keep maxlerebourg in `go.mod` and only change Traefik `moduleName` — rejected; Yaegi GOPATH import would not match.

2. **Keep package clause; omit `basePkg`.** Last path segment is unchanged, so Traefik’s derived `basePkg` stays `crowdsec_bouncer_traefik_plugin`. Alternative: set `basePkg` explicitly — unnecessary.

3. **Catalog-form compose becomes localPlugins.** Pattern is `docker-compose.local.yml`: `--experimental.localplugins.bouncer.modulename=<go.mod>` and `./:/plugins-local/src/<go.mod>` (examples use `./../../:`). Uncomment that pair where it already exists; add it on root `docker-compose.yml` and `examples/behind-proxy/docker-compose.yml` (no comments today). Delete `experimental.plugins.bouncer` + `version=`. Keep routing alias `bouncer` / `plugin.bouncer`. Alternative: leave catalog pins — Traefik fails download. Alternative: keep maxlerebourg catalog identity in examples — operators still cannot load *this* tree.

4. **Already-local trees: path only.** `geoenrich-decisions`, real e2e, mock e2e: retarget `modulename` and `plugins-local/src/<module>`. Do not retarget `traefik-geoblock`.

5. **Kubernetes values and binary-vm.** Switch `experimental.plugins` + `version` to `experimental.localPlugins` (no version) at the new moduleName. Document that the operator must mount or copy sources to `plugins-local/src/<module>`. Do not ship `version=` of this fork.

6. **README working example is localPlugins.** Dest README already names the new module under catalog `plugins` + `version: vX.Y.Z` (that GET 404s). Replace the working static block with `localPlugins` + alias `bouncer`. Add a short note: catalog GET of this module 404s; the catalog will not list a fork; hosts that already use upstream `experimental.plugins.bouncer` must register this fork under a different alias (`localPlugins.crowdsec` + `plugin.crowdsec`).

7. **`displayName`:** `CrowdSec Bouncer Traefik Plugin (david-garcia-garcia)`. Distinguishes from upstream `Crowdsec Bouncer Traefik Plugin`. Non-empty.

8. **Usage packet after apply, not in this design’s product code.** `knowledge/devdocs/core_plugin_middleware.md` still says “Do not change `.traefik.yml` `import`” (constructor-move ticket). Implement / devdocsimpact changes that line to keep import matching `go.mod`.

9. **Mechanical rewrite; no `New` behavior change.** Do not add `sync.Once` or package globals. `pkg/reclaim` stays as dest.

## Risks / Trade-offs

- [Catalog examples stop downloading upstream v1.7.1] → Accepted. Those compose files are how an operator runs *this* tree; a catalog pin of this module 404s. Operators who want catalog maxlerebourg keep using upstream’s docs.
- [Same alias as upstream `plugins.bouncer` overwrites] → Document a different operator alias. In-tree stays `bouncer`.
- [Operators with an existing local bind-mount at the old path] → They must move the mount. No dual-path compatibility layer.
- [Yaegi tests fail if CI GOPATH and `go.mod` disagree] → Same owner string in both places; Main already requires checkout equals `go.mod`.

## Migration Plan

1. Change `go.mod` `module`, rewrite imports and depguard, set `.traefik.yml` `import` and `displayName`.
2. Point Main + race checkout/working-directory at `go/src/<module>`.
3. Flip compose/e2e/k8s/binary-vm/README as above.
4. Update live specs in this change folder (archive stays).
5. Rollback: revert the commit; Traefik load paths return to maxlerebourg.

## Open Questions

None — explore decisions stand.
