# Explore
IssueKey: 2026-09-21-bouncer-instance-severance

## Concepts

Three jobs on one Yaegi `New` (`plugin.go`): Open a LAPI Client, Open an AppSec Client, bounce this router. Today they are inseparable.

```
  Config (one YAML object)
       │
       ├─ lapiEnabled + secrets     → lapi.OpenStream/OpenLive → publish named slot
       ├─ lapiEnabled + instance    → subscribe (no Open)
       ├─ appsecEnabled + secrets   → appsec.Open → publish named slot
       ├─ appsecEnabled + instance  → subscribe
       ├─ bouncerHold               → ServeHTTP 503
       └─ bouncerEnabled            → Bouncer.ServeHTTP (else next)
```

Units:

- `pkg/configuration` — public Traefik JSON keys; `ValidateParams`; `GetVariable` by struct field name.
- `plugin.go` — `New` snapshot, bindCtx, which Opens run, named publish.
- `pkg/lapi` — reclaim Client by SessionHex; exclusive store `createdBy` today is Traefik `name`.
- `pkg/appsec` — reclaim Client by listener identity.
- `pkg/bouncer` — per-router `ServeHTTP`; today holds `*Client` pointers from `New`.
- Named slot (new, process table) — operator name → live `*lapi.Client` / `*appsec.Client`; Peek on request; Openers bind; subscribers do not.
- `README.md` / `docs/modes.md` / `examples/` / `tests/e2e/` — operator YAML.

Call sites to migrate (product tree, not `openspec/changes/archive` or other `devstate/`): Config JSON tags and struct fields in `pkg/configuration/configuration.go` (80+ keys); `plugin.go`; `pkg/lapi/**`, `pkg/appsec/**`, `pkg/bouncer/**` field reads; `zzz_*.go` and `tests/e2e/mock/scenarios/**/dynamic.yml`; `examples/**`; `README.md`. Roots searched: `pkg`, `plugin.go`, `zzz_*.go`, `tests/e2e`, `examples`, `README.md`, `docs`. Live specs that name old keys: `openspec/specs/core_plugin_middleware_bouncer`, `core_plugin_middleware_config-validation`, `core_plugin_lapi_failure-action`, `core_plugin_appsec_failure-action`, `core_plugin_appsec_client`, `core_plugin_lapi_reclaim-key`, `core_plugin_lapi_scope-union`.

Reproduce: not reproduced — this is a commissioned surface change, not a failing path.

Outside facts: Traefik calls `New` per router handler build, map order, `knowledge/research/ext_traefik_plugins_yaegi-constructor/notes.md`. Reclaim Peek does not bind: `knowledge/devdocs/std_go_reclaim.md`.

## Decisions

- Domain-prefixed YAML (`lapi*` / `appsec*` / `bouncer*`); drop `crowdsec` prefix; no old-key aliases. `log*` and `httpTimeoutSeconds` stay.
- `lapiEnabled` default true, `appsecEnabled` default false, `bouncerEnabled` default false (today `enabled`), `bouncerHold` default false.
- `lapiMode` is `live|stream|none|alone` only. Delete `appsec` mode. AppSec-only is `lapiEnabled: false` + `appsecEnabled: true`.
- Open vs subscribe: secrets on this middleware → Open and publish `lapiInstance` (empty = Traefik name). Enabled + instance + no secrets → subscribe. Both flags false skip that leg.
- Named slot is a process alias beside identity reclaim, not a replacement. Identity reclaim still owns tickers. Slot Peek on every bounce request (`atomic.Value`, not `atomic.Pointer[T]`).
- DecisionStore `createdBy` becomes the LAPI instance name so two Openers of the same instance can share; a second instance name on the same SessionHex still fails `New`.
- Missing slot at request time is `bouncerLapiFailureAction` / `bouncerAppsecFailureAction` (already per-router).
- `bouncerHold`: Open, then 503 + log; do not call `next`. Dummy router still needed when no bouncing router Opens.
- `lapiScopeHeaders` is opener-only (stream fetch). Bouncing subscribers do not union into `scopes=`.
- Do not add decision remap in this change.
- Rejected: `lapiMode=bouncer` as the only bounce path (human dropped it). Rejected: `"nil"` instance sentinel (YAML null). Rejected: blocking `New` until the slot exists (deadlocks Traefik constructor). Rejected: bouncers as reclaim holders of the Client (would keep a deleted holder’s stream alive).

Live contract: fold `core_plugin_middleware_bouncer`, `core_plugin_middleware_config-validation`, `core_plugin_lapi_failure-action`, `core_plugin_appsec_failure-action`, `core_plugin_appsec_client`, `core_plugin_lapi_reclaim-key`, `core_plugin_lapi_scope-union`. New leaf for named instance publish/subscribe.

## Open questions

- Q: Which process table holds the operator instance name?
  Rank: additive asked — new alias beside reclaim; Desired names subscribe-by-name
  Decision: resolved — process named slot keyed `lapi-instance:` / `appsec-instance:` plus the operator name; Openers Publish after identity Open; bounce path Peek; Yaegi-safe `atomic.Value`
  By: explore

- Q: What happens when the bouncing router `New`s before the named client exists?
  Rank: bounded asked — Bouncer construct/ServeHTTP enumerated in `pkg/bouncer` + `plugin.go`; Desired names startup order
  Decision: resolved — `New` stores the name only; ServeHTTP Peeks; miss uses that router’s LAPI/AppSec failure action
  By: explore

- Q: What HTTP status does `bouncerHold` write?
  Rank: additive asked — new hold path; Desired names placeholder reject
  Decision: resolved — 503, log that this middleware holds clients and does not bounce; not 403
  By: explore

- Q: Does `lapiScopeHeaders` still union from every bouncing router?
  Rank: bounded asked — live union in `pkg/lapi/liveheaderscopes.go` (one Client method + OpenStream register); Desired split fetch vs bounce
  Decision: assumed — opener registers scopes at Open; subscribers do not register; shrinking/growing union from bounce routers is dropped
  By: explore

- Q: Is decision remapping in this change?
  Rank: additive incidental — no existing remap unit; Out of scope on requirement.md
  Decision: resolved — skip; cheap bouncer field later
  By: explore
