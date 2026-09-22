## Why

Every Traefik middleware `New` today opens LAPI and AppSec, unions stream scopes from whoever constructed first, and passes concrete client pointers into the bouncer. Operators cannot name shared backends, split bounce policy from client ownership, or construct a bouncing router before its named owner without deadlocking. Beta behaviour change is acceptable; public YAML key names stay as they are.

## What Changes

- Add named LAPI and AppSec **instance slots** (`crowdsecLapiInstanceName`, `crowdsecAppsecInstanceName`) with per-leg enable flags (`crowdsecLapiEnabled` defaults false), publish/subscribe fan-out via Yaegi-safe `atomic.Value`, and exclusive slot publish per leg table.
- Split **ownership Open keys** (middleware name plus full client knob set) from **slot names** (what bouncers subscribe to) and from **SessionHex** (DecisionStore; stream adds canonical `crowdsecLapiStreamScopes`).
- **Late bind**: bouncer `New` never waits; `ServeHTTP` only `Load`s bound clients; `streamStartupBlock` on the request path means every subscribed backend is published (503 until then when true).
- Drop `crowdsecMode: appsec`; use `crowdsecLapiEnabled: false` plus AppSec enabled. Opener-only `crowdsecLapiStreamScopes`; retire live-router header-scope union for stream poll.
- Remove DecisionStore `createdBy` rejection for a second Traefik name on the same SessionHex; allow sharing via named slots. AppSec reclaim includes middleware name (two names, same knobs → two Clients).
- Lifecycle logs (stable `msg` lines) for real e2e A–D, slot collision ERROR, stream collision WARN.
- **BREAKING** behaviour: config validation (E2/E3), reload/reclaim semantics, stream scopes, AppSec cross-name sharing, `streamStartupBlock` placement.
- Land debt notes `knowledge/debt/2026-09-22-stream-startup-block-rethink.md` and `knowledge/debt/2026-09-22-appsec-tls-follows-lapi.md`; README severance section.

## Capabilities

### New Capabilities

- `core_plugin_middleware_instance-slots`: Dual LAPI/AppSec slot tables, Publish/Subscribe/Clear, generation-aware unpublish, `plugin.go` orchestration, lifecycle log contract.

### Modified Capabilities

- `core_plugin_middleware_config-validation`: New instance/enable fields, open-vs-subscribe validation (E2/E3), remove `appsec` mode acceptance.
- `core_plugin_middleware_bouncer`: `atomic.Value` late bind, request-path startup block, mode from loaded LAPI client, remove exclusive store `New` failure and direct client ownership at construct.
- `core_plugin_lapi_reclaim-key`: Middleware-scoped ownership Open key, SessionHex scope list and Redis rules, remove foreign-store owner reject; interval/CAPI/defaultDecisionSeconds client-key rules.
- `core_plugin_lapi_scope-union`: Replace live-router union with opener `crowdsecLapiStreamScopes` only.
- `core_plugin_appsec_client`: Middleware name in reclaim key; knob change is new Client (not AdoptTransport for timeout/TLS).
- `build_e2e_pester_crowdsec-stack`: `instance_severance.Tests.ps1`, writable dynamic config for reload cases T/L/R/N/F/C.

## Impact

- New `pkg/instance` (name per house style), `plugin.go`, `pkg/configuration`, `pkg/bouncer`, `pkg/lapi` (session, identity, stream), `pkg/appsec/session`.
- Unit tests S1–S5, P1–P4, I1–I3; replace/adjust named tests in `zzz_session_test.go` files.
- Real e2e harness: writable file provider for reload proofs.
- Devdocs: middleware, reclaim-key, scope-union packets updated on implement/devdocsimpact; README in implement.
