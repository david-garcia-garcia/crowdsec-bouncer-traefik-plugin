# Explore

## Concepts

Captcha is a third named reclaim leg beside LAPI and AppSec. Dest already uses `lapi*` / `appsec*` / `bouncer*` public keys (PR 137). The live bounce/failure surface is `bouncerEnabled` and `bouncerLapiFailureAction` / `bouncerAppsecFailureAction`, not spec `enabled` / `crowdsecLapiFailureAction`.

### Reproduce

**Reproduced:** captcha is per-bouncer today, not a named slot.

- `captchaEnabled` / `captchaInstanceName` — not found. Roots: worktree `*.go`, `examples/**`, `tests/**` (only `requirement.md` / `ticket/source.md`).
- `plugin.go` `openOwned` / `claimOwned` / `reclaim.Watch` handle `legLAPI` and `legAppSec` only (lines 38–40, 106–117, 123–174).
- `bouncer.New` always constructs `captcha.Client` from this router’s `BouncerCaptcha*` fields (`pkg/bouncer/bouncer.go` 92, 117–140). `ServeHTTP` uses `b.captchaClient`, not `atomic.Value` / `reclaim.Unbox`.
- Path run: `go test ./pkg/bouncer/ -count=1 -timeout 60s -run TestNew_CaptchaSiteverifyTimeout` — **pass** (0.091s). Those tests call `bouncer.New` and read `route.captchaClient.HTTPClientForTest()`; timeout comes from this config, not a published slot.

Empty provider today: `Client.New` sets `Valid = provider != ""` and returns (`pkg/captcha/captcha.go` 73–75). `handleRemediationServeHTTP` bans when `!captchaClient.Valid` (`pkg/bouncer/bouncer.go` 558–560). A captcha-kind verdict with no provider is a ban.

### Today

```
Traefik New(name)
    │
    ├─ ValidateParams (captcha keys when BouncerCaptchaProvider set)
    ├─ lapi.Prepare / appsec.Prepare  (empty instance name → Traefik name when owned)
    ├─ openOwned + claimOwned         (LAPI, AppSec only)
    ├─ subscribe = bouncerEnabled && instanceName != ""
    ├─ bouncer.New(..., subscribeLAPI, subscribeAppSec)
    │     └─ captcha.Client.New(this router’s BouncerCaptcha*)
    └─ Watch alias:lapi|appsec:<name>  (no captcha Watch)
```

| Unit | Path | Job |
| --- | --- | --- |
| Constructor | `plugin.go` | Own/claim/watch LAPI and AppSec. Bounce subscribe is `BouncerEnabled` plus a non-empty LAPI or AppSec name. |
| Config | `pkg/configuration/configuration.go` | Own flags `lapiEnabled` / `appsecEnabled`; bounce `bouncerEnabled`; captcha settings are per-router `bouncerCaptcha*`. `validateFailureAction` allows `captcha` only when `BouncerCaptchaProvider` is set. `validateLegOpenVsSubscribe` is LAPI and AppSec only. |
| Bouncer | `pkg/bouncer/bouncer.go` | Two `atomic.Value` bindings (LAPI, AppSec). Local `*captcha.Client`. Startup-block 503 checks subscribed LAPI/AppSec only. Remediation header lives on the Bouncer and is copied into the captcha client at `New`. |
| LAPI empty-name fill | `pkg/lapi/client.go` `Prepare` | `LapiEnabled && trim(name)==""` → Traefik name. |
| AppSec empty-name fill | `pkg/appsec/client.go` `Prepare` | Returns if `!AppsecEnabled`; otherwise empty name → Traefik name. Same owned-only fill as LAPI. |
| Captcha client | `pkg/captcha/captcha.go` | Provider siteverify HTTP, template, gate secret, custom paths. Stores `remediationCustomHeader`. Not a reclaim value. |
| Gate cookie | `pkg/captcha/gate.go` | One cookie name `crowdsec_captcha_gate` path `/` for every client. Out of scope to change. |
| Slots | `pkg/reclaim/default.go` + utilities `SetAlias` / `Watch` | Opaque `alias:<leg>:<name>`. Groups `lapi` / `appsec` only. |

### Target

```
Traefik New(name)
    │
    ├─ captcha.Prepare  (empty name → Traefik name only when captchaEnabled)
    ├─ openOwned / claimOwned / Watch  + group captcha
    ├─ subscribeCaptcha = bouncerEnabled && captchaInstanceName != ""
    ├─ bouncer.New(..., subscribeCaptcha)
    │     └─ no local Client from subscriber keys
    └─ ServeHTTP Loads captchaBound; missing + captcha verdict → ban
         startupBlock on → 503 for unpublished subscribed captcha name
```

```
  ┌──────────────┐  Open + SetAlias     ┌─────────────────┐
  │ captcha owner│─────────────────────►│ alias:captcha:N │
  │ captchaEnabled│                      │ Watchers        │
  └──────────────┘                      └────────▲────────┘
                                                 │
  ┌──────────────┐  Watch (no holder)            │
  │ bouncing     │───────────────────────────────┘
  │ bouncerEnabled + captchaInstanceName
  │ header / failure actions stay here
  └──────────────┘
```

### Call sites (bounded)

| Contract | Count | Roots searched |
| --- | --- | --- |
| `plugin.go` own/claim/watch | **1** orchestration file; **2** `Watch` sites; `openOwnedLeg` / `claimOwnedLeg` switch **2** cases (`lapi`, `appsec`) | `plugin.go`, `pkg/reclaim/**`, `zzz_plugin_test.go`, `zzz_traefikemulator_test.go` |
| `bouncer.New` captcha construct | **1** production (`pkg/bouncer/bouncer.go`); **2** tests via helper (`pkg/bouncer/zzz_http_timeout_test.go`) | `plugin.go`, `pkg/**/*.go`, `zzz_*.go` for `bouncer.New(` |
| `captcha.Client` field / `&captcha.Client{}` | **1** production field; **6** test struct literals in `pkg/bouncer/zzz_*.go` | `pkg/bouncer/**`, `pkg/captcha/**` |
| `validateFailureAction` | **2** calls (`BouncerLapiFailureAction`, `BouncerAppsecFailureAction`) | `pkg/configuration/configuration.go`, `pkg/configuration/zzz_configuration_test.go` |
| `validateEnabledCaptchaSettings` / provider-set owner checks | **1** production helper; **20+** table rows in `zzz_configuration_test.go` plus `zzz_plugin_test.go` (2) | `pkg/configuration/**`, `zzz_plugin_test.go` |
| Startup-block unpublished name | **2** checks (LAPI, AppSec) in `ServeHTTP` | `pkg/bouncer/bouncer.go` |
| Remediation header on `captcha.Client` | **1** store in `Client.New`; **3** writes (`ServeHTTP` ×2, `WriteSolvedRedirect`) | `pkg/captcha/captcha.go`, `pkg/bouncer/bouncer.go` |
| In-repo `bouncerCaptchaProvider` operator YAML | **4** example files (`examples/captcha/*`, `examples/custom-captcha/*`); **4** e2e (`tests/e2e/real/config/docker-compose.test.yml` ×2 middlewares, `tests/e2e/mock/scenarios/captcha*/dynamic.yml`, mock README) | `examples/**`, `tests/**` |

### Outside facts

In-tree: `knowledge/devdocs/core_plugin_middleware.md`, `core_plugin_middleware_instance-slots.md`, `std_go_reclaim.md`, `core_plugin_middleware_config-validation.md`, captcha gate/routing/siteverify packets. Research: `knowledge/research/index_ext_traefik-middleware-utilities.md` (alias APIs already in the shim). No new vendor clone.

### Language deltas (consume; no packet write)

No hard gap — Slot / Publish / Subscribe / LAPI Client / AppSec Client / Bouncer / Failure action already exist. Do not write packets this phase.

| Term | Today (packet) | This change would need |
| --- | --- | --- |
| **Slot** | One named LAPI or AppSec publish target | Third table `captcha`; `shared` may exist in all three |
| **Bouncer** | Two optional `atomic.Value` bindings | Third captcha binding; `ServeHTTP` Loads it |
| **Two configuration axes** | `lapiEnabled` / `appsecEnabled` own; `bouncerEnabled` bounces | Third own axis `captchaEnabled` |
| Captcha siteverify client | “Keep that client per-Bouncer. Do not reclaim it.” (`core_plugin_middleware.md`) | Owner Opens; subscribers Watch; do not construct on bounce-only |
| **Failure action** | `captcha` legal when provider is set | `captcha` legal when this router has a captcha instance name |

Fuzzy (parked, not Language): whether owner captcha settings stay `bouncerCaptcha*` or become `captcha*` — Decision below keeps dest keys.

## Decisions

- **Seam:** Third reclaim leg. `plugin.go` adds group `captcha` to `openOwned` / `claimOwned` / `Watch`. Do not rewrite the two-leg helpers into a generic N-leg registry.
- **Identity owner:** After the change, the reclaim alias table (group `captcha`, `alias:captcha:<name>`) owns which client a router uses. The owner middleware `Open`s and `SetAlias`s. Subscribers `Watch` only. Do not reconstruct from subscriber `BouncerCaptcha*`.
- **Live public keys:** Honor dest. Bounce is `bouncerEnabled`. Failure actions stay `bouncerLapiFailureAction` / `bouncerAppsecFailureAction`. New own-axis keys are `captchaEnabled` / `captchaInstanceName` (same pattern as `lapiEnabled` / `lapiInstanceName`). Keep existing `bouncerCaptcha*` as owner-read settings; do not rename them to `captcha*`.
- **Empty name:** Copy LAPI’s explicit fill: `captchaEnabled && trim(name)==""` → Traefik name. AppSec’s fill is the same owned-only rule behind an early return.
- **Subscriber keys:** Ignored. Owner-style checks (provider, keys, gate secret, loadable template) run only when `captchaEnabled`.
- **Missing client:** `bouncer.New` does not build a fallback local client for bounce-only. Startup block on → 503 for an unpublished subscribed captcha name. Startup block off → continue; a captcha verdict with no published client is a ban (same as today’s `!Valid`).
- **Header:** Remediation header stays on the Bouncer. Lift `remediationCustomHeader` off the shared `captcha.Client` onto the call sites so a subscriber does not inherit the owner’s header.
- **Cookie:** Leave `crowdsec_captcha_gate` path `/` as-is (out of scope).
- **Rejected:** Implicit own from a set provider (would hide `captchaEnabled`). Block `New` until a captcha owner exists. Reconstruct captcha on the subscriber when the slot is empty. Rename dest `bouncer*` / `lapi*` / `appsec*` back to spec `enabled` / `crowdsecLapiFailureAction`. Second cookie namespace.
- **Live contract:** `openspec/specs/core_plugin_middleware_instance-slots` (two tables), `core_plugin_middleware_bouncer` (captcha MUST stay per-Bouncer and MUST NOT be reclaimed), `core_plugin_middleware_config-validation`, `core_plugin_lapi_failure-action` / `core_plugin_appsec_failure-action` (`captcha` requires provider), plus captcha-gate / captcha-routing / captcha-siteverify. Propose updates those leaves. Not `no live contract`.

## Open questions

- Q: Default of `captchaEnabled` and how existing `bouncerCaptchaProvider`-only YAML migrates?
  Rank: bounded asked — new own flag plus in-repo operator YAML that today treats provider-set as own; 4 example files and 4 e2e hits (roots: `examples/**`, `tests/**`, `pkg/**`, `*.go` for `bouncerCaptchaProvider`)
  Decision: assumed — default false, matching `lapiEnabled` / `appsecEnabled`. No implicit own from provider. Single-router operators set `captchaEnabled: true` (empty name fills to the Traefik name). Update those in-repo examples and e2e here.
  By: explore

- Q: Does captcha need `reclaim.Open` (holder) or only a heap pointer plus `SetAlias`?
  Rank: bounded asked — “Same axes as the other legs” and holder-with-bounce-off; 2 existing legs in `plugin.go` `openOwned` / `claimOwned` / `Watch`; searched `plugin.go`, `pkg/reclaim`
  Decision: assumed — Open + SetAlias + Watch like LAPI/AppSec. `SetAlias` maps an ownership key. Holder with `bouncerEnabled: false` still Opens. Ownership key = middleware name plus instance-owned captcha knobs (not the slot name, not bounce/failure/header/startup-block). Sleep/Wake may be no-ops (no ticker).
  By: explore

- Q: What is the blast radius of sharing one captcha client (siteverify HTTP client, template, grace clock)?
  Rank: additive asked — “Subscribers of one name share that page, that verifier, those widget paths, and that grace”
  Decision: assumed — share is safe: `http.Client` is concurrent-safe; `template.Execute` is concurrent-safe; `Check` / `Validate` / `ServeHTTP` do not mutate after `New`; grace uses `time.Now()` per call. One idle pool per instance is intended. Cookie overwrite across two instances on one host stays out of scope.
  By: explore

- Q: Who already owns which captcha client this router uses (the slot identity)?
  Rank: additive asked — new captcha slot this change creates; “One middleware owns the captcha client and publishes it under a name”
  Decision: resolved — none today (each Bouncer constructs from local `BouncerCaptcha*`). After: reclaim alias group `captcha` is the owner; reuse `SetAlias` / `Watch`. The owner middleware Opens. Subscribers do not re-derive the client from leftover keys.
  By: explore

- Q: Should `bouncer.New` keep constructing a local captcha client after captcha is a named leg?
  Rank: bounded asked — changes the existing `bouncer.New` contract; 1 production caller (`plugin.go`) and 2 timeout tests (`pkg/bouncer/zzz_http_timeout_test.go`); searched `plugin.go`, `pkg/**/*.go`, `zzz_*.go` for `bouncer.New(`
  Decision: resolved — no local construct on bounce-only. Owner Opens and publishes. Missing published client + captcha verdict = ban when startup block is off (“When captcha is missing”).
  By: explore

- Q: How does a captcha verdict remediate today when `BouncerCaptchaProvider` is empty?
  Rank: additive asked — “A captcha verdict on a router that did not subscribe is a ban”
  Decision: resolved — `Valid` is false when provider is empty; `handleRemediationServeHTTP` bans. After the change, a typed-nil published client is the same ban (or 503 if startup block and subscribed).
  By: explore

- Q: Copy AppSec’s empty-name fill or LAPI’s `enabled && empty` fill?
  Rank: additive asked — “An empty instance name is filled with this middleware's Traefik name only when captchaEnabled is true”
  Decision: resolved — LAPI’s explicit `owned && empty` (AppSec is the same rule: `Prepare` returns before fill when `!AppsecEnabled`). Implement `captcha.Prepare` that way.
  By: explore

- Q: Failure-action `captcha` gate: instance name or provider?
  Rank: bounded asked — “That value is legal only when this router has a captcha instance name”; 2 `validateFailureAction` call sites in `pkg/configuration/configuration.go`; searched `pkg/configuration`, `pkg/bouncer`, `plugin.go`
  Decision: resolved — legal when this router has a captcha instance name (after owner fill). Dest key names stay `bouncerLapiFailureAction` / `bouncerAppsecFailureAction`. A captcha verdict without a subscribe is still a ban at runtime.
  By: explore

