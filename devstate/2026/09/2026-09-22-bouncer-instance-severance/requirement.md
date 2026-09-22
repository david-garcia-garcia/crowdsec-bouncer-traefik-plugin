# Requirement
IssueKey: 2026-09-22-bouncer-instance-severance

## Problem
Each Traefik middleware `New` opens LAPI and/or AppSec and bounces on one object (`plugin.go`). Reclaim keys are LAPI URL+key / identity hashes (`pkg/lapi/session.go`, `pkg/lapi/identity.go`), not operator-chosen names. There is no `crowdsecLapiInstanceName`, `crowdsecLapiEnabled`, or `crowdsecLapiStreamScopes` on `configuration.Config` (`pkg/configuration/configuration.go`). Operators cannot share one LAPI/AppSec client across routes while keeping per-route bounce knobs (remediation header, failure actions, captcha, trusted IPs, `decisionScopeHeaders`). Traefik may construct a bouncing router before another middleware that would open the same backend; blocking `New` on a missing owner would deadlock.

## Current (code)
- `plugin.go` — `New` validates, `lapi.Prepare` / `appsec.Prepare`, then `OpenStream` / `OpenLive` when mode is not `appsec`, else skips LAPI; opens AppSec when `CrowdsecAppsecEnabled`; always passes concrete `*lapi.Client` and `*appsec.Client` into `bouncer.New`. No subscribe/publish slot layer.
- `pkg/configuration/configuration.go` — `CrowdsecMode` includes `appsec` (`AppsecMode`). `Enabled` defaults via `New()`. No instance-name or LAPI-enabled fields. `StreamStartupBlock` exists (default true in `New()`).
- `pkg/bouncer/bouncer.go` — Holds direct `lapiClient` / `appsecClient` pointers; copies `crowdsecMode` and `decisionScopeHeaders` at `New`. `ServeHTTP` uses those fields; no `atomic.Value` late bind.
- `pkg/lapi/session.go` — `OpenStream` reclaims by `SessionKey` (session + Redis params); `rejectForeignStoreOwner` fails `New` when another Traefik name owns the same `SessionHex` store. Stream poll scopes union from registered `decisionScopeHeaders` (`pkg/lapi/zzz_scopeunion_test.go`), not a separate opener list.
- `pkg/lapi/client_stream.go` — `StreamStartupBlock` blocks inside client/stream startup path when true, not a bouncer-only “subscribed backends published” guard on `ServeHTTP`.
- `pkg/lapi/identity.go` — Live/none Open key uses `SessionHex` + identity payload; comments omit several knobs the spec wants on the ownership key.
- `pkg/appsec/session.go` — AppSec reclaim by listener identity; two middleware names with identical knobs can share one Client (`pkg/appsec/zzz_session_test.go` documents today’s reclaim behavior).
- `tests/e2e/real/` — No `instance_severance.Tests.ps1`; reload-heavy A–D cases from the spec are not present.

## Desired
Keep existing public key names (no `lapi*` / `bouncer*` rename in this change). Add named LAPI/AppSec slots (`crowdsecLapiInstanceName`, `crowdsecAppsecInstanceName`), `crowdsecLapiEnabled` (default false), and opener-only `crowdsecLapiStreamScopes`. Split **ownership** (Open + publish slot) from **bounce** (`enabled`): subscribers bind via Publish/Subscribe into per-leg `atomic.Value` on the bouncer; `New` never waits; `ServeHTTP` only Loads. Ownership Open key = middleware name + full client settings per leg; slot name is publish/subscribe only. Generation-aware Clear on grace `Close`; mutex-guarded publish with `crowdsec instance name taken` when another middleware holds the slot. Remove `crowdsecMode: appsec`; AppSec-only = `crowdsecLapiEnabled: false` + `crowdsecAppsecEnabled: true`. Adjust `SessionHex` / store identity, stream collision WARN, lifecycle INFO/DEBUG logs, config validation errors, and README for dummy vs shared vs all-in-one setups per `ticket/source.md`. Land debt notes `knowledge/debt/2026-09-22-stream-startup-block-rethink.md` and `knowledge/debt/2026-09-22-appsec-tls-follows-lapi.md`. Required proof: real-stack e2e in `tests/e2e/real/` (file-provider reload) plus listed `go test` cases for SessionHex, AppSec ownership, and LAPI client knobs.

## Affected
- `plugin.go`, `pkg/configuration/`, `pkg/bouncer/`, new or extended slot/registry package under `pkg/`
- `pkg/lapi/` (Open keys, `SessionHex`, stream scopes, collision logging, store lifecycle)
- `pkg/appsec/` (ownership key semantics)
- `tests/e2e/real/`, `pkg/lapi/zzz_session_test.go` and related tests, README

## Out of scope
- Renaming all config keys to domain prefixes; old-key aliases
- New decision-remapping product behavior beyond existing knobs
- Traefik core changes; mandatory dummy routers
- Using slot name alone as Client reclaim key
- Full YAML knob rename follow-on from the spec’s “later” note

## Unknowns
- Exact package layout for dual slot tables (LAPI vs AppSec) and Yaegi-safe subscriber lists
- README section structure after behavior change
- Whether existing `2026-09-21-bouncer-instance-severance` branch work should be merged or superseded (not in caller spec)

## Tensions
- Spec requires `rejectForeignStoreOwner`-style `New` failure on same `SessionHex` with different Traefik names to become allowed when sharing via named slots and `SessionHex` rules change — today `pkg/lapi/session.go` rejects that case.
- Spec moves `streamStartupBlock` to bouncer request-path “subscribed client published” semantics; today `pkg/lapi/client_stream.go` applies it at client open/stream startup.
- Spec requires middleware name in AppSec ownership key (two names → two Clients); today `pkg/appsec/zzz_session_test.go` expects reclaim across names for identical knobs.
- Spec lists debt files not yet on `origin/master` under `knowledge/debt/` (only unrelated debt notes exist in the worktree).
