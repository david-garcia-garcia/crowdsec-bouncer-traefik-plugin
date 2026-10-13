## Why

Live leaf `core_plugin_middleware_instance-reclaim` dumps four units (session prefix, first-wins settings hash, last-`New` transport adopt, per-router Bouncer policy) under a 4th part that names none of them. Later changes keep folding into that folder. Human approved a rename; Naming cannot put Open-key and Bouncer on one legal leaf.

## What Changes

- Split the dump. New `core_plugin_lapi_reclaim-key` owns session prefix, first-wins settings hash, `PeekLivePrefix` warn-and-wire, sleep-snapshot new key, and `lapi.Client` `ProcessGrace` 30s.
- Rename the remaining middleware unit `core_plugin_middleware_instance-reclaim` → `core_plugin_middleware_bouncer` (Yaegi `CreateConfig`/`New`, Bouncer does not own the stream, Redis fail-closed, live-cache TTL).
- Fold the concurrent last-write `AdoptTransport` scenario into `core_plugin_lapi_connection`.
- Drop failure-action-per-router duplicate scenarios from the dump onto existing `core_plugin_lapi_failure-action` (no rewrite of that owner SHALL).
- Delete the live dump folder after the new leaves exist. Archive folders keep the historical id.
- Cite the new spec ids on the named usage packets at implement / `devdocsimpact`. Delete `knowledge/debt/2026-09-17-rename-core-plugin-middleware-instance-reclaim.md` when implement lands.
- Specs-and-docs only. No `pkg/` edits. Behaviour stays `master`.

## Capabilities

### New Capabilities

- `core_plugin_lapi_reclaim-key`: How this plugin keys a reclaimed `lapi.Client` (session prefix + first-wins hash, `PeekLivePrefix`, sleep snapshot, LAPI `ProcessGrace`).
- `core_plugin_middleware_bouncer`: What `New` returns and holds per router (Yaegi constructors, Bouncer does not own the stream, Redis fail-closed, live TTL).

### Modified Capabilities

- `core_plugin_lapi_connection`: Concurrent `AdoptTransport` last-writes the stored transport and idle-closes the value it replaced.
- `core_plugin_middleware_instance-reclaim`: REMOVED — dump leaf retired after the split (Removed unit). Remaining SHALLs live on `core_plugin_middleware_bouncer` and `core_plugin_lapi_reclaim-key`.

## Impact

- Live `openspec/specs/` leaves named above. Archive `openspec/changes/archive/**` keeps `core_plugin_middleware_instance-reclaim`.
- Usage `knowledge/devdocs/core_plugin_middleware.md`, `knowledge/devdocs/core_plugin_lapi_connection.md`, `knowledge/devdocs/index_core_plugin.md` (cite new ids at implement / `devdocsimpact`).
- This run’s `devstate/2026/09/2026-09-17-rename-instance-reclaim-leaf/specs.md`.
- Debt file `knowledge/debt/2026-09-17-rename-core-plugin-middleware-instance-reclaim.md` (delete on implement).
- No `pkg/` edits. Do not write `core_plugin_lapi_usage-metrics`, `core_plugin_appsec_*`, or `core_plugin_middleware_captcha-gate`.
- No **BREAKING** public JSON/YAML keys.
