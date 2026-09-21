# Explore
IssueKey: 2026-09-17-rename-instance-reclaim-leaf

## Concepts

Traefik calls `New` once per router-handler build and cancels that constructor `ctx` on reload (`ext_traefik_plugins_yaegi-constructor`). This process already binds that `ctx` through in-tree `pkg/reclaim` (`std_go_reclaim_context-lease`, `std_go_reclaim.md`). There is no `core_plugin_reclaim` packet; usage lives on `core_plugin_middleware.md`. This ticket is specs-and-docs only. Do not add `sync.Once` or a package global. Do not edit `pkg/`.

Live leaf `core_plugin_middleware_instance-reclaim` is a dump. Its `spec.md` currently states six requirement blocks that are not one unit:

```
Yaegi CreateConfig/New on module root
        │
        ▼
  New(ctx) ──► OpenStream / OpenLive ──► Bouncer
        │              │                    │
        │              ▼                    ▼
        │     reclaim Open key         per-router policy
        │     (prefix + hash)          (action / Redis / TTL)
        │              │
        │              ▼
        │     AdoptTransport last-wins
        │     (already on lapi_connection)
        ▼
  constructor ctx is the reclaim holder
```

The four units the ticket names collapse to **two remaining jobs** plus **two already-owned siblings**:

| Cluster | Job | Live owner today |
| --- | --- | --- |
| Session prefix + first-wins settings hash + `PeekLivePrefix` + sleep snapshot new key + LAPI `ProcessGrace` | How this plugin keys a reclaimed `lapi.Client` | dumped in `instance-reclaim` |
| Yaegi constructors + Bouncer does not own the stream + Redis fail-closed + live TTL | What `New` returns and holds per router | dumped in `instance-reclaim` |
| Last `New` `AdoptTransport` | Replaceable LAPI HTTP+auth | already `core_plugin_lapi_connection` |
| Per-router LAPI failure action | Enum + Bouncer owner | already `core_plugin_lapi_failure-action` |

Session prefix and settings hash are **one** Open-key job (`SessionKey` = `SessionPrefix` + hash; live/none `Key` = `lapi:` + `IdentityHex`). A 4th part that names only `session-key` or only `settings-hash` hides the other half. `instance-reclaim` names none of them.

FindSpecHost Search candidates (wide set): `core_plugin_middleware_instance-reclaim`, `core_plugin_lapi_connection`, `core_plugin_lapi_failure-action`, `core_plugin_lapi_stream-lease`, `std_go_reclaim_context-lease`. Fenced (do not write): `core_plugin_lapi_usage-metrics`, `core_plugin_appsec_*`, `core_plugin_middleware_captcha-gate`. Active OpenSpec changes: none.

Usage packets (`core_plugin_middleware.md`, `core_plugin_lapi_connection.md`, `index_core_plugin.md`) already name those units and do **not** cite the spec id. Sibling live spec **bodies** do not cite the id either. Archive folders keep the historical id by design. Family map lists `core` / `plugin` / `middleware` and `lapi`; leaves omitted.

Human approved the rename. Folding the remaining unique SHALLs back onto `instance-reclaim` or onto another vague 4th part is not a rename.

## Decisions

- **Split**, not one 4th-part rename. One legal leaf cannot name both the LAPI Open key and the per-router Bouncer. Debt options `settings-hash` / `session-key` / `instance-reclaim` each hide a unit or stay vague.
- Legal names (Naming: `core` + `plugin` + component + leaf; domains.md already has `plugin`):
  1. **new** `core_plugin_lapi_reclaim-key` — session prefix, first-wins hash, `PeekLivePrefix` warn-and-wire, sleep snapshot opens a new key, `lapi.Client` uses `ProcessGrace` 30s.
  2. **rename remaining middleware unit** `core_plugin_middleware_instance-reclaim` → `core_plugin_middleware_bouncer` — Yaegi `CreateConfig`/`New` on the module root; Bouncer does not own the stream; Bouncer holds Redis fail-closed and live-cache TTL.
- FindSpecHost verdicts (propose re-runs before each folder write):

```
verdicts:
  - { deltaId: lapi-reclaim-key, new, core_plugin_lapi_reclaim-key, high, candidates: [core_plugin_middleware_instance-reclaim, core_plugin_lapi_connection, core_plugin_lapi_failure-action, core_plugin_lapi_stream-lease, std_go_reclaim_context-lease] }
  - { deltaId: middleware-bouncer, new, core_plugin_middleware_bouncer, high, candidates: [core_plugin_middleware_instance-reclaim, core_plugin_lapi_failure-action] }
  - { deltaId: transport-adopt-concurrent, fold, core_plugin_lapi_connection, high, candidates: [core_plugin_lapi_connection, core_plugin_middleware_instance-reclaim] }
  - { deltaId: failure-action-per-router-dup, fold, core_plugin_lapi_failure-action, high, candidates: [core_plugin_lapi_failure-action, core_plugin_middleware_instance-reclaim] }
```

  `middleware-bouncer` is **Removed unit** on the old family: after LAPI-key SHALLs leave, the leftover is Bouncer/`New`. Do not keep `instance-reclaim`.
- Sibling SHALL move: **yes, one**. The concurrent last-write `AdoptTransport` scenario lives only on the dump leaf; fold it into `core_plugin_lapi_connection` (that leaf already owns replaceable transport). Failure-action-per-router SHALLs already live on `core_plugin_lapi_failure-action`; drop the duplicate scenarios from the dump, do not rewrite that sibling’s owner SHALL.
- Do not fold the Open-key cluster into `core_plugin_lapi_connection` (past one-to-three-requirement fold). Do not fold Redis fail-closed / live TTL into `core_plugin_lapi_failure-action` (that leaf is the enum + owner, not a policy bag).
- Do not fold onto `core_plugin_lapi_stream-lease` (lease TTL floor, not Open key) or `std_go_reclaim_context-lease` (table contract, not this plugin’s key).
- Fenced leaves do not cite this id today. Implement must not write them. If Sync later shows a citation, stop `blocked`.
- AppSec `ProcessGrace` sentence on the dump leaf: do not copy a SHALL into fenced `core_plugin_appsec_*`. `core_plugin_lapi_reclaim-key` states `lapi.Client` waits 30s. AppSec same-table stays where the AppSec leaf already is.
- Spec-vs-code: do not edit `pkg/` or “fix” DestBranch behaviour. Observed looseness (not treated as a behaviour bug this run): spec summarizes Redis as host/auth/db/enabled while `streamSettings` / `identity` also hash `LapiRedisReadHosts`; live/none `identity` omits `lapiScopeHeaders` while stream hash includes it. Note only.
- Client address stays `pkg/ip.GetRemoteIP` (`core_plugin_ip`). The dump’s “Client address SHALL…” line is not a new identity owner. Move it only as a cross-ref if the Open-key leaf still mentions visitor IP; do not re-derive `RemoteAddr`.
- Usage packets already describe the units. Explore produces no Language and no usage edit. Implement / later `devdocsimpact` cite the new spec ids on those packets and on this run’s `specs.md` only.
- Archive `openspec/changes/archive/**` keeps `core_plugin_middleware_instance-reclaim`. Delete `knowledge/debt/2026-09-17-rename-core-plugin-middleware-instance-reclaim.md` when implement lands; close this run’s `issues.md` row.
- Research: `ext_traefik_plugins_yaegi-constructor` and `ext_traefik-middleware-utilities_packages` already answer `New` and reclaim. No new research folder.
- No `pkg/` edits. Do not touch `devstate/2026/09/2026-09-17-lapi-transport-router-policy/`.

## Open questions

- Q: One rename to a precise 4th part, or a split? Which legal name(s)?
  Decision: resolved — split. New `core_plugin_lapi_reclaim-key`. Rename remaining `core_plugin_middleware_instance-reclaim` → `core_plugin_middleware_bouncer`. Fold concurrent `AdoptTransport` into `core_plugin_lapi_connection`. Drop failure-action duplicates onto existing `core_plugin_lapi_failure-action`.
  By: explore

- Q: Must a live sibling spec body move a SHALL after the split?
  Decision: resolved — yes, one: concurrent last-write `AdoptTransport` → `core_plugin_lapi_connection`. Failure-action-per-router is already there; drop dups only. No other sibling body rewrite.
  By: explore

- Q: Does the live leaf text disagree with `e6cc9ab` / DestBranch code?
  Decision: assumed — field-list looseness only (`LapiRedisReadHosts` hashed but unnamed in the spec; live `identity` omits `lapiScopeHeaders`). Do not edit spec text to “fix” code or the reverse this run. Behaviour stays `master`.
  By: explore

- Q: Does a rename force an edit inside a fenced leaf?
  Decision: resolved — no citation today on usage-metrics, `core_plugin_appsec_*`, or `core_plugin_middleware_captcha-gate`. If Sync later shows one, stop `blocked`. Do not write those folders.
  By: explore

- Q: Who already owns identity (visitor address, LAPI cursor, reclaim key, Host)?
  Decision: assumed — visitor address is `pkg/ip.GetRemoteIP` (reuse; do not parse `RemoteAddr`). LAPI stream cursor is CrowdSec’s bouncer row (hashed key + outbound IP); do not reconstruct. Reclaim Open key is this plugin’s `SessionKey` / `Key` (`session.go` / `identity.go`). Traefik `New` `ctx` is the reclaim holder. This rename does not invent a second owner.
  By: explore

- Q: Keep the Open-key cluster under `middleware`, or move it to `lapi`?
  Decision: resolved — `core_plugin_lapi_reclaim-key`. The key is LAPI Client identity, not the Bouncer. A `core_plugin_middleware_reclaim-key` would be the wrong family.
  By: explore

- Q: What happens to the dump leaf’s AppSec `ProcessGrace` sentence?
  Decision: assumed — do not edit fenced AppSec specs. New LAPI leaf states `lapi.Client` / `ProcessGrace` only.
  By: explore
