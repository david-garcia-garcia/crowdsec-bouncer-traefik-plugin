## 1. Live catalog

- [x] 1.1 Add `openspec/specs/core_plugin_lapi_reclaim-key/spec.md` from this change’s ADDED (Purpose + Open-key / grace requirements)
- [x] 1.2 Add `openspec/specs/core_plugin_middleware_bouncer/spec.md` from this change’s ADDED (Yaegi constructors + Bouncer)
- [x] 1.3 Apply the `core_plugin_lapi_connection` MODIFIED requirement (concurrent `AdoptTransport` last-write) onto the live leaf
- [x] 1.4 Delete live `openspec/specs/core_plugin_middleware_instance-reclaim/` after 1.1–1.3 exist. Do not rewrite archive folders.

## 2. Live dependents

- [x] 2.1 Cite the new spec ids on `knowledge/devdocs/core_plugin_middleware.md`, `knowledge/devdocs/core_plugin_lapi_connection.md`, and `knowledge/devdocs/index_core_plugin.md`
- [x] 2.2 Delete `knowledge/debt/2026-09-17-rename-core-plugin-middleware-instance-reclaim.md` and mark this run’s `issues.md` take row `[x]` with `Taken:`
- [x] 2.3 Do not write `core_plugin_lapi_usage-metrics`, `core_plugin_appsec_*`, or `core_plugin_middleware_captcha-gate`. If Sync shows a citation of the dump id there, stop `blocked`.

## 3. Verify

- [x] 3.1 Grep live product paths (not `openspec/changes/archive/`, not `devstate/`) for `core_plugin_middleware_instance-reclaim` — zero hits
- [x] 3.2 Confirm no `pkg/` edits in the apply
- [x] 3.3 `openspec validate --change rename-instance-reclaim-leaf`
