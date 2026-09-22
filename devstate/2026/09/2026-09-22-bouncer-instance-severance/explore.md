# Explore

## Concepts

New capability on branch `2026-09-22-bouncer-instance-severance` vs `destBranch: master`. **Reproduce:** not reproduced / N/A — no failing test; the gap is missing severance behavior and e2e coverage.

### Today (master-shaped worktree)

```
Traefik New(name)
    │
    ├─ configuration.ValidateParams + lapi.Prepare + appsec.Prepare
    ├─ bindCtx := WithCancel(constructor ctx)  // reclaim holders
    ├─ crowdsecMode ≠ appsec → lapi.OpenStream | OpenLive(bindCtx, …, name, …)
    ├─ crowdsecAppsecEnabled → appsec.Open(bindCtx, …, name, …)
    └─ bouncer.New(…, *lapi.Client, *appsec.Client)  // direct pointers; mode copied at New
```

| Unit | Path | Job today |
|------|------|-----------|
| Traefik constructor | `plugin.go` | Single middleware opens LAPI (except `appsec` mode skip), optional AppSec, always passes concrete clients into bouncer |
| Config | `pkg/configuration/configuration.go` | `CrowdsecMode` includes `appsec`; no `crowdsecLapiEnabled` / instance names; `StreamStartupBlock` default true |
| Bouncer | `pkg/bouncer/bouncer.go` | Holds `lapiClient` / `appsecClient`; `crowdsecMode` + `decisionScopeHeaders` at `New`; `ServeHTTP` uses them |
| LAPI reclaim | `pkg/lapi/session.go`, `identity.go`, `client_stream.go` | Open key = `SessionKey` / live `Key`; `rejectForeignStoreOwner` fails second Traefik name on same `SessionHex`; stream poll scopes from **live router union** (`liveHeaderScopes` via `registerLiveHeaderScopes` in `OpenStream`) |
| AppSec reclaim | `pkg/appsec/session.go` | Listener identity key; **two middleware names + same knobs → one Client** (`zzz_session_test.go`) |
| Reclaim shim | `pkg/reclaim/default.go` | Process-wide `OpenWithHooks` / `Peek`; 30s grace |
| E2E | `tests/e2e/real/` | No `instance_severance.Tests.ps1`; reload A–D not covered |

### Target (requirement.md)

```
Traefik New(name)
    │
    ├─ Prepare + new enable/instance fields + validation (E2/E3, drop appsec mode)
    ├─ Per leg: own (Open → Publish slot) OR subscribe (Subscribe → atomic.Value)
    ├─ Ownership Open key = middleware name + full client knob set (≠ slot name)
    ├─ DecisionStore still SessionHex (LAPI); canonical stream scopes on opener list
    └─ bouncer: Load atomic clients; streamStartupBlock on request path = subscribed published?
```

| New / moved unit | Likely home | Job |
|------------------|-------------|-----|
| Slot tables (LAPI + AppSec) | TBD (`pkg/instance` or similar) | Publish / Subscribe / Clear with mutex; subscriber `[]*atomic.Value`; publisher middleware name per slot |
| Orchestration | `plugin.go` | Child ctx per `New`; open owned legs; publish; subscribe when `enabled` + name set; fail + rollback publish on collision |
| Bouncer bind | `pkg/bouncer/bouncer.go` | `atomic.Value` per leg; no reclaim Bind on subscribe; mode from loaded LAPI client |
| LAPI Open key | `pkg/lapi/` | Widen ownership key (intervals, CAPI, defaultDecisionSeconds, …); drop foreign-store owner reject for named sharing; `crowdsecLapiStreamScopes` drives poll; SessionHex includes canonical scope list in stream |
| AppSec Open key | `pkg/appsec/` | Middleware name in key; knob change → new Client (no cross-name share) |
| Lifecycle logs | LAPI/AppSec/bouncer | Stable `msg` lines for real e2e grep |
| Debt | `knowledge/debt/2026-09-22-*.md` | Required in scope; not on worktree yet (only older debt notes) |

**Call sites that must migrate (bounded enumeration):**

| Contract change | Count | Roots searched |
|-----------------|-------|----------------|
| `plugin.go` → `lapi.Open*` / `appsec.Open` / `bouncer.New` wiring | **1** production (`plugin.go`); tests via `New` in `zzz_plugin_test.go`, `zzz_constructor_test.go` | `plugin.go`, `**/*_test.go` |
| `bouncer.New(..., *Client, *Client)` signature | **1** caller (`plugin.go`) | same |
| `rejectForeignStoreOwner` / exclusive store | **1** call chain (`OpenStream` → `openDecisionStoreExclusive`) | `pkg/lapi/` |
| Stream scope union from bouncer headers | **1** registration (`OpenStream` → `registerLiveHeaderScopes`) | `pkg/lapi/session.go`, `liveheaderscopes.go` |
| AppSec reclaim across names | tests + `appsec.Open` key builder | `pkg/appsec/` |

**Outside facts:** requirement appendix + in-tree devdocs (`core_plugin_middleware.md`, `core_plugin_lapi_reclaim-key.md`, `core_plugin_lapi_scope-union.md`). Traefik constructor order: requirement assumes publish completes all `New`s before traffic — no extra research filed.

```
  ┌─────────────┐     Publish(name)      ┌──────────────┐
  │ LAPI owner  │───────────────────────►│ LAPI slot    │
  │ middleware  │     Open(ownKey)       │ subscribers  │
  └─────────────┘                        │ []*atomic.V  │
         │                               └──────▲───────┘
         │ SessionHex                         │ Subscribe
         ▼                                      │
  ┌─────────────┐                        ┌──────┴───────┐
  │ DecisionStore│                       │ Bouncer      │
  └─────────────┘                        │ ServeHTTP    │
                                         └──────────────┘
  (AppSec: parallel table, no shared DecisionStore)
```

## Decisions

- **Seam:** Add named slot Publish/Subscribe layer between `plugin.go` and existing `lapi`/`appsec` Open + reclaim; keep `pkg/reclaim` for ownership Open, not for slot fan-out.
- **Bouncer bind:** Two `atomic.Value` fields on the bouncing middleware (Yaegi-safe); `ServeHTTP` only `Load`s; move `streamStartupBlock` semantics to bouncer request path (published check), remove blocking from `startStream` when spec says so.
- **LAPI identity split:** Slot name for fan-out; middleware name + settings for Client Open; `SessionHex` for DecisionStore (add canonical stream scopes + Redis rules per spec); remove `rejectForeignStoreOwner` behavior that blocks second middleware on same store.
- **Stream scopes:** Opener-only `crowdsecLapiStreamScopes`; retire header-map union for `scopes=` (remove or stop registering bouncer maps on OpenStream).
- **AppSec ownership:** Include Traefik middleware name in Open key; replace tests that expect cross-name reclaim.
- **Config:** Add `crowdsecLapiEnabled`, instance names, `crowdsecLapiStreamScopes`; default `crowdsecLapiEnabled` false; drop `appsec` mode (map to LAPI off + AppSec on); validation per Open vs subscribe table.
- **Tests:** Real e2e file `tests/e2e/real/instance_severance.Tests.ps1` + writable dynamic config; go tests S1–S5, P1–P4, I1–I3 replace/adjust named tests in `pkg/lapi/zzz_session_test.go`, `pkg/appsec/zzz_session_test.go`.
- **Rejected:** `crowdsecMode: bouncer` only bounce path; dummy routers mandatory; block `New` until owner exists; slot name as sole Client reclaim key; channel-based push (requirement).
- **Live contract:** `no live contract` — no delta spec folder yet for this change.

## Open questions

- Q: Which package owns the dual LAPI/AppSec slot tables and Publish/Subscribe API?
  Rank: additive asked — new subsystem in scope (“Named LAPI and AppSec slots”, Late bind); criterion names publish/subscribe
  Decision: assumed — add a dedicated package under `pkg/` (e.g. `pkg/instance`) colocated with tests; `plugin.go` orchestrates only; propose picks exact name following go house style.
  By: explore

- Q: Should prior branch work `2026-09-21-bouncer-instance-severance` be merged or treated as superseded?
  Rank: additive incidental — no In-scope line; not blocking design
  Decision: assumed — implement from `requirement.md` on IssueKey branch; do not merge stale branch unless human redirects.
  By: explore

- Q: How should README document placeholder vs shared-owner vs all-in-one setups?
  Rank: additive asked — Constraints: “README must explain optional dummy vs bouncing subscribers vs one-middleware all-in-one”
  Decision: assumed — extend existing plugin/middleware configuration README with one severance section and the YAML shapes from requirement (T1–T3, shared owner, AppSec-only, placeholder).
  By: explore

- Q: What happens to `liveHeaderScopes` when bouncers no longer register `decisionScopeHeaders` on `OpenStream`?
  Rank: bounded asked — changes existing stream poll contract; 1 registration site (`OpenStream` in `pkg/lapi/session.go`); migrates to opener list + SessionHex scope hash here
  Decision: assumed — delete union-driven poll scopes for stream; poll uses `crowdsecLapiStreamScopes` only; keep bouncer-side header extraction unchanged; bind-time WARN when bouncer map exceeds opener list.
  By: explore

- Q: Must implement land `knowledge/debt/2026-09-22-stream-startup-block-rethink.md` and `knowledge/debt/2026-09-22-appsec-tls-follows-lapi.md` in the same PR?
  Rank: additive asked — “Assumed technical debt that must be created as part of the scope”
  Decision: assumed — yes, both files in implement before archive; content as requirement table describes.
  By: explore
