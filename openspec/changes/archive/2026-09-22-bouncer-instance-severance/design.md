## Context

Traefik calls `New` in arbitrary order inside one config publish. Reclaim today keys LAPI Clients by session/Redis hash and rejects a second middleware name on the same DecisionStore. Bouncers hold direct `*Client` pointers and copy `crowdsecMode` at construct. Stream `scopes=` unions all live routers' `decisionScopeHeaders`. Explore locked slot layer + `atomic.Value`, SessionHex split from ownership Open key, opener-only stream scopes, `pkg/instance` for tables.

## Goals / Non-Goals

**Goals**

- Operator-named LAPI/AppSec slots; one middleware may own clients, bounce only, or both.
- Never block `New` waiting for a publisher; bind off request path.
- Generation-aware slot Clear; multi-leg publish rollback on collision.
- Spec-listed e2e and go test matrix from requirement.md.

**Non-Goals**

- Domain-prefix YAML renames; Traefik core; mandatory dummy routers; slot name as sole Client reclaim key.

## Decisions

| Topic | Choice | Rationale |
|-------|--------|-----------|
| Slot API owner | `pkg/instance` | One job for dual tables; `plugin.go` orchestrates only (explore Q1). |
| Fan-out | `[]*atomic.Value` per slot, mutex on Publish/Clear | Yaegi-safe; requirement rejects channels. |
| Holder ctx | Child `context.WithCancel(constructor ctx)` per `New` | One cancel on any failure after Open; explore seam. |
| LAPI Open key | Traefik name + full client knob set | Settings reload must not Wake wrong Client. |
| DecisionStore | SessionHex unchanged owner; drop `rejectForeignStoreOwner` | Two ownership keys may share store. |
| Stream scopes | `crowdsecLapiStreamScopes` on opener; hash in SessionHex (stream) | Retire header union registration. |
| AppSec Open key | Add middleware name; no cross-name share | P1–P4 tests. |
| `streamStartupBlock` | Bouncer request path; "ready" = published for this change | Debt file records name/TTL follow-up. |
| Prior branch `2026-09-21-*` | Do not merge | Implement from requirement on IssueKey branch. |

## Risks / Trade-offs

- **Short gap serving sleeping Client after settings change (R2)** → Acceptable per requirement; bound log marks switch.
- **Store/clear race on failed multi-leg publish** → Mutex holds Store until rollback unpublish completes.
- **Two stream owners same host+key** → WARN only (C1), not `New` failure.

## Migration Plan

- Operators using implicit share-by-key keep working via all-in-one middleware or explicit `shared` instance names.
- `crowdsecMode: appsec` → `crowdsecLapiEnabled: false`, `crowdsecAppsecEnabled: true` (E4 / T4).
- Beta: document breaking behaviour in README severance section.

## Open Questions

- Deferred to debt files for "ready" beyond published and AppSec TLS inherit (implement must create both debt paths).
