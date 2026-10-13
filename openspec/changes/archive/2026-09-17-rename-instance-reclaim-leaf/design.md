## Context

See `proposal.md` Why. Live dump `openspec/specs/core_plugin_middleware_instance-reclaim/spec.md` states six requirement blocks that are not one unit. Behaviour already matches `origin/master` (`e6cc9abaa0e9246398cd82fa2273fbe320f0185d`). This change is specs-and-docs only.

FindSpecHost Search (propose, before each folder write). Live candidates: `core_plugin_middleware_instance-reclaim`, `core_plugin_lapi_connection`, `core_plugin_lapi_failure-action`, `core_plugin_lapi_stream-lease`, `std_go_reclaim_context-lease`. Fenced (do not write): `core_plugin_lapi_usage-metrics`, `core_plugin_appsec_*`, `core_plugin_middleware_captcha-gate`. Active OpenSpec changes: none. Live sibling bodies and fenced leaves do not cite the dump id.

```
verdicts:
  - { deltaId: lapi-reclaim-key, new, core_plugin_lapi_reclaim-key, high, candidates: [core_plugin_middleware_instance-reclaim, core_plugin_lapi_connection, core_plugin_lapi_failure-action, core_plugin_lapi_stream-lease, std_go_reclaim_context-lease] }
  - { deltaId: middleware-bouncer, new, core_plugin_middleware_bouncer, high, candidates: [core_plugin_middleware_instance-reclaim, core_plugin_lapi_failure-action] }
  - { deltaId: transport-adopt-concurrent, fold, core_plugin_lapi_connection, high, candidates: [core_plugin_lapi_connection, core_plugin_middleware_instance-reclaim] }
  - { deltaId: failure-action-per-router-dup, fold, core_plugin_lapi_failure-action, high, candidates: [core_plugin_lapi_failure-action, core_plugin_middleware_instance-reclaim] }
  - { deltaId: instance-reclaim-retire, fold, core_plugin_middleware_instance-reclaim, high, candidates: [core_plugin_middleware_instance-reclaim, core_plugin_middleware_bouncer] }
```

`middleware-bouncer` is Removed unit on the old family. `failure-action-per-router-dup` is fold with no body rewrite (owner SHALL already present). `instance-reclaim-retire` is REMOVED so archive deletes the live dump folder.

## Goals / Non-Goals

**Goals:**

- Two remaining jobs on legal 4th parts: LAPI Open key, per-router Bouncer/`New`.
- One sibling SHALL move: concurrent last-write `AdoptTransport` → `core_plugin_lapi_connection`.
- Live dump folder gone after archive. Historical archive ids stay.

**Non-Goals:**

- Any `pkg/` edit or DestBranch behaviour change.
- Folding Open-key into `core_plugin_lapi_connection` or Redis/TTL into `core_plugin_lapi_failure-action`.
- Folding onto `core_plugin_lapi_stream-lease` or `std_go_reclaim_context-lease`.
- Rewriting `core_plugin_lapi_failure-action` owner SHALL.
- Writing fenced leaves. Editing `devstate/2026/09/2026-09-17-lapi-transport-router-policy/`.
- Fixing spec-vs-code field-list looseness (`RedisCacheReadHosts` hashed but unnamed; live `identity` omits `decisionScopeHeaders`).
- Usage Language this phase (implement / `devdocsimpact` cite the new spec ids).

## Decisions

1. **Split, not one 4th part.** One legal leaf cannot name both Open-key and Bouncer. Debt options `settings-hash` / `session-key` / `instance-reclaim` each hide a unit or stay vague.
2. **Open-key family is `lapi`.** `SessionKey` / `Key` identify the Client. A `core_plugin_middleware_reclaim-key` would be the wrong family.
3. **Remaining middleware leaf is `bouncer`.** After key SHALLs leave, leftover is Yaegi `New` + Bouncer policy. Do not keep `instance-reclaim`.
4. **Concurrent `AdoptTransport` folds into `connection`.** That leaf already owns replaceable transport. Add the dump-only concurrent last-write scenario there.
5. **Failure-action dups drop, no rewrite.** Per-router action already lives on `core_plugin_lapi_failure-action`. No delta file for that leaf.
6. **AppSec `ProcessGrace` stays fenced.** New LAPI leaf states `lapi.Client` / `ProcessGrace` only.
7. **Visitor address stays `pkg/ip.GetRemoteIP`.** Cross-ref on the Open-key leaf. Do not re-derive `RemoteAddr`.
8. **Do not “fix” DestBranch text vs code.** Note looseness only.

## Risks / Trade-offs

- [Archive still contains `instance-reclaim`] → Accepted. Historical ids stay. Live dependents update; archive does not.
- [Fenced leaf gains a citation after Sync] → Stop `blocked`. Do not write those folders.
- [Later changes keep folding into a vague leftover] → Removed unit deletes the dump leaf in this change.

## Migration Plan

No operator JSON/YAML key change. Rollback is revert of the spec/docs commits. Implement deletes the debt file and the live dump folder after the new leaves exist.
