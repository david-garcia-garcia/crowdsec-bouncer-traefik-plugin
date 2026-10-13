# Explore

## Concepts

This tree still presents Go, Yaegi, Traefik, and Main CI as `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin`. DestBranch is already split: `README.md` static `moduleName` and `docker-compose.local.yml` use `github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin`; `go.mod`, `.traefik.yml` `import`, Main GOPATH checkout, e2e bind-mounts, and most examples do not.

```
Traefik load (two sources, one alias map)
─────────────────────────────────────────
experimental.plugins.<alias>     → GET plugins.traefik.io/public/download/<module>/<version>
experimental.localPlugins.<alias> → ./plugins-local/src/<module>  (no version)

NewBuilder: catalog first, then local. Same alias = local overwrites.

manifest.import  MUST be a prefix of moduleName
go.mod module    MUST equal that import (Yaegi GOPATH)
CI checkout      MUST sit at go/src/<that module>
basePkg          path.Base(import) with "-" → "_"  (last segment unchanged)
```

Measured DestBranch: `go.mod` module and `.traefik.yml` `import` are still maxlerebourg. Main CI checks out `go/src/github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin`. `Makefile` `yaegi_test` is `yaegi test -v .` (cwd). Catalog compose pins `experimental.plugins.bouncer` + `version=v1.7.1`.

Measured catalog (2026-09-18 GET): maxlerebourg `@v1.7.1` → 200. This fork’s module `@v1.7.1` and `@vX.Y.Z` → 404. Official catalog create checklist: **forks are not added**. This repo is a fork. Publishing is out of scope and would not list anyway.

`ext_traefik_plugins_localplugins/` and `ext_traefik_plugins_yaegi-constructor/` already cover bind-mount layout and `CreateConfig`/`New`. Missing catalog download / alias overwrite / fork-ban → wrote `knowledge/research/ext_traefik_plugins_catalog/`.

No in-tree compose collision: examples that load this tree use alias `bouncer`; `geoenrich-decisions` adds a second alias `geoblock` for a different module. Do not invent a second in-tree middleware family.

This work does not set client address, user, tenant, Host, or trust hop. It does not change reclaim, tickers, or `New` lifetime. Do not add `sync.Once` or package globals. `pkg/reclaim` and `std_go_reclaim` stay as dest.

Usage packet `core_plugin_middleware.md` still says “Do not change `.traefik.yml` `import`” (that was the constructor-move ticket). After apply it must say keep `import` matching `go.mod`. Do not rewrite that packet as if dest already moved.

Live specs that SHALL the old import: `build_ci_github_module-path`, `build_ci_github_race-detector`, `core_plugin_middleware_bouncer`. Archive folders stay. `core_plugin_middleware_bouncer` names the Bouncer type, not the Traefik alias — do not rename.

No active OpenSpec change (`openspec list` empty).

## Decisions

- Retarget every Go/Yaegi identity to `github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin`: `go.mod` `module`, all in-tree imports of that module, `.traefik.yml` `import`, Main CI checkout + working-directory, e2e/example `modulename` and `plugins-local/src/<module>`.
- Keep package clause `crowdsec_bouncer_traefik_plugin`. `basePkg` stays derived from the last path segment (unchanged). Do not add `basePkg`.
- Keep in-tree alias `bouncer` / `plugin.bouncer`. No second middleware family.
- Catalog-form Docker compose (root `docker-compose.yml` and `examples/*/docker-compose.yml` that already have commented localPlugins + bind-mount): flip to `localPlugins` + new module path so they load this tree. Do not leave a catalog pin of this unpublished module. Do not keep maxlerebourg as the example identity.
- `geoenrich-decisions`, real e2e, mock e2e: already local; retarget the path only.
- README: working static example becomes `localPlugins` (this tree). Keep alias `bouncer` there. Add a note that catalog GET of this module 404s, the catalog will not list a fork, and operators who keep upstream `experimental.plugins.bouncer` must register this fork under a **different** alias (`localPlugins.crowdsec` + `plugin.crowdsec` is the ticket example).
- Kubernetes values and binary-vm: switch to `localPlugins` + new moduleName and say the operator must mount/copy sources to `plugins-local/src/<module>`. Do not ship a catalog `version=` of this fork.
- `.traefik.yml` `displayName`: `CrowdSec Bouncer Traefik Plugin (david-garcia-garcia)`. Non-empty (Traefik rejects empty). Distinguishes from upstream’s `Crowdsec Bouncer Traefik Plugin`.
- Live specs: rewrite the old-import SHALL/WHEN to the new module. Do not touch `openspec/changes/archive/**`.
- After apply, usage `core_plugin_middleware.md` “Do not change import” → keep import matching `go.mod` (implement / devdocsimpact).
- `renovate.json` stays (out of scope). Noted as follow-up.
- Do not retarget `traefik-middleware-utilities` or `traefik-geoblock`. Do not rename `pkg/`. Do not change ban/captcha/LAPI behavior.

## Open questions

- Q: Who already owns this plugin’s Go/Yaegi module identity (not client address / user / tenant / Host / trust hop)?
  Decision: resolved — `go.mod` `module` is the owner. `.traefik.yml` `import` must be a prefix of Traefik `moduleName` and must match that module. Main CI checkout path must equal `go/src/` plus that module. Reuse those outputs; do not invent a fourth path. Request identity is out of scope.
  By: explore

- Q: Does this change Traefik `New` process lifetime (shared ticker, cache, HTTP client)?
  Decision: resolved — no. Import rewrite only. Keep reclaim on the constructor bind context. Do not add `sync.Once` or package globals.
  By: explore

- Q: Catalog-form examples (`experimental.plugins.bouncer` + `version=v1.7.1`) after `modulename` changes — local bind-mount, leave catalog pins, or accept broken catalog examples?
  Decision: assumed — convert in-repo runnable compose to `localPlugins` + bind-mount at the new module path (same pattern as `docker-compose.local.yml`). Keep alias `bouncer`. Do not leave maxlerebourg pins. Do not ship a catalog download of this fork (measured 404; catalog will not list a fork). README / k8s / binary-vm document localPlugins as the working install.
  By: explore

- Q: What exact `displayName` text distinguishes from upstream?
  Decision: assumed — `CrowdSec Bouncer Traefik Plugin (david-garcia-garcia)`. Ticket only said distinguish. Traefik requires non-empty `displayName`.
  By: explore

- Q: Is there an in-tree compose alias collision that needs a second middleware family?
  Decision: resolved — no. `geoblock` is a different plugin. Keep `bouncer` in-tree. Document a different operator key only for hosts that already use upstream `plugins.bouncer`.
  By: explore

- Q: Should README keep a catalog `experimental.plugins` snippet with `version: vX.Y.Z` for this fork?
  Decision: assumed — no as the working example. Catalog download of this module 404s and forks are not listed. Show `localPlugins`. Mention the 404 / fork-ban so operators do not copy the dest catalog block.
  By: explore

- Q: Should live OpenSpec archive folders that still name maxlerebourg be rewritten?
  Decision: resolved — no. Ticket forbids `openspec/changes/archive/**`. Only live specs that SHALL the old import.
  By: explore

- Q: Should `renovate.json` `depNameTemplate` move in this change?
  Decision: assumed — no. Ticket left it out of scope. Follow-up: `knowledge/debt/2026-09-18-renovate-depname-maxlerebourg.md`.
  By: explore

- Q: Should `core_plugin_middleware_bouncer` be renamed because “bouncer” is also the Traefik alias?
  Decision: assumed — no. The leaf names the per-router Bouncer type. Vague-name Issues do not apply. Update the import WHEN only.
  By: explore
