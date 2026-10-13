# Requirement
IssueKey: 2026-09-17-rename-instance-reclaim-leaf

## Problem
The live leaf `openspec/specs/core_plugin_middleware_instance-reclaim` names none of the four units it now describes (session prefix, first-wins settings hash, last-`New` transport adopt, per-router Bouncer policy). Later changes keep folding into that folder.

## Current (code)
- Live leaf dumps all four units in one `spec.md`. Path: `openspec/specs/core_plugin_middleware_instance-reclaim/spec.md`.
- Stream/alone session prefix is mode + LAPI scheme/host/path + key (CAPI machine+password in alone). Path: `pkg/lapi/session.go`.
- Reclaim `Open` key is that prefix plus a hash of remaining first-wins settings (intervals, Redis host/auth/db, `updateMaxFailure`, CAPI scenarios, `decisionScopeHeaders`). Path: `pkg/lapi/session.go`.
- Policy, `StreamStartupBlock`, HTTP timeout, and LAPI TLS are off that hash. A live joiner with a different remaining hash is warn-and-wire (`PeekLivePrefix`, first `New` wins those knobs). Path: `pkg/lapi/session.go`.
- After bind, `AdoptTransport` last-wins LAPI HTTP+auth on the same Client. Path: `pkg/lapi/client_http.go`.
- Bouncer holds per-router LAPI failure action, Redis fail-closed, and live-cache TTL. Path: `pkg/bouncer/bouncer.go`.
- Yaegi `CreateConfig` / `New` stay on the module-root package. Path: `plugin.go`.
- Usage packets already describe those four units without citing the spec id. Path: `knowledge/devdocs/core_plugin_middleware.md`, `knowledge/devdocs/core_plugin_lapi_connection.md`, `knowledge/devdocs/index_core_plugin.md`.
- Sibling live specs describe overlapping units and do not cite this spec id. Path: `openspec/specs/core_plugin_lapi_connection/spec.md`, `openspec/specs/core_plugin_lapi_failure-action/spec.md`.
- Fenced leaves do not cite this spec id. Path: `openspec/specs/core_plugin_lapi_usage-metrics/spec.md`, `openspec/specs/core_plugin_appsec_client/spec.md`, `openspec/specs/core_plugin_appsec_failure-action/spec.md`, `openspec/specs/core_plugin_appsec_bot-detection/spec.md`, `openspec/specs/core_plugin_middleware_captcha-gate/spec.md`.
- Family map lists `core` / `plugin` / `middleware` and omits leaves. Path: `openspec/specs/map.md`.
- Parked rename (human now approved): `knowledge/debt/2026-09-17-rename-core-plugin-middleware-instance-reclaim.md`.
- Dest HEAD that implements this behaviour: `e6cc9abaa0e9246398cd82fa2273fbe320f0185d` (`origin/master`).

## Desired
Decide, via Naming and FindSpecHost, one rename to a precise legal 4th part or a split into more than one leaf. Record the reasoning. Do not fold onto another vague name. Update every live dependent found: sibling `openspec/specs/` leaves, the named `knowledge/devdocs/` packets, and this run’s `devstate/**/specs.md` only. Keep historical spec ids under `openspec/changes/archive/`. Behaviour stays what `master` already implements; spec-vs-code disagreement is a follow-up, not an edit of either. When implement lands, delete the debt file and close the row on this run’s `issues.md` and delivery card.

## Affected
- `openspec/specs/core_plugin_middleware_instance-reclaim/`
- Sibling live specs that overlap the four units (`core_plugin_lapi_connection`, `core_plugin_lapi_failure-action`) if FindSpecHost requires a cross-link or a moved SHALL
- `knowledge/devdocs/core_plugin_middleware.md`
- `knowledge/devdocs/core_plugin_lapi_connection.md`
- `knowledge/devdocs/index_core_plugin.md`
- `knowledge/debt/2026-09-17-rename-core-plugin-middleware-instance-reclaim.md` (delete on implement)
- This run’s `devstate/2026/09/2026-09-17-rename-instance-reclaim-leaf/specs.md` (when propose writes it)

## Out of scope
- Any file under `pkg/`
- `openspec/specs/core_plugin_lapi_usage-metrics/`
- `openspec/specs/core_plugin_appsec_*` and `core_plugin_middleware_captcha-gate`
- Product behaviour changes versus `origin/master`
- Rewriting spec ids inside `openspec/changes/archive/`
- Editing or staging `devstate/2026/09/2026-09-17-lapi-transport-router-policy/`
- Other runs’ `devstate/**/specs.md`

## Unknowns
- Whether Naming + FindSpecHost pick one 4th part or a split, and the legal name(s).
- Whether a live sibling spec body (not just a folder rename) must move a SHALL after the split.
- Whether the live leaf text disagrees with `e6cc9ab` anywhere; ticket says note that, do not fix it here.
- Whether a rename ever forces an edit inside a fenced leaf (none cite this id today; if one appears after Sync, stop `blocked`).

## Tensions
- Debt file offered “settings-hash vs session-key vs instance-reclaim” after a human pick. This ticket says both one rename and a split are acceptable; pick what the grammar supports.
- Usage packets already name the four units; the leaf folder name does not.
- Archive folders keep the old id by design; live dependents must still be updated.
- Sibling tickets own usage-metrics, AppSec, and captcha-gate. A forced edit there is `blocked`, not a silent cross-ticket write.
