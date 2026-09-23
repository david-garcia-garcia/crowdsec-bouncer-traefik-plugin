# Explore

## Concepts

A bouncing router that never `Watch`es captcha can still see captcha kind. Dest already bans that request. The operator is not told the router never subscribed.

### Reproduce

**BAN reproduced.** Same degrade branch as dest’s unpublished-client rule.

- `go test . -count=1 -timeout 60s -run 'TestNew_CaptchaSubscriberBeforePublishBans|TestNew_CaptchaSubscriberBeforePublishBlocks'` — **pass** (0.094s). Unpublished subscribed + forced `c` → 403, no challenge; startup-block on → 503.
- `go test ./pkg/bouncer/ -count=1 -timeout 60s -run 'TestNew_BounceOnlyDoesNotConstructCaptcha|TestServeHTTP_forcedDecisionCaptchaWhenLookupIsNotBan'` — **pass** (0.072s). Bounce-only `New` leaves captcha nil. Forced `c` with a Valid client still serves the page.

**Missing WARN from source, not a failing test.** `handleRemediationServeHTTP` bans when `captchaClient == nil || !captchaClient.Valid` and does not `Warn` (`pkg/bouncer/bouncer.go` 591–594). No existing test asserts a WARN on `!subscribeCaptcha`. Operator-silence is that missing call.

### Today

```
captcha kind arrives
  ├─ LAPI / remap kind c
  ├─ forced header c
  └─ failure-action captcha  (ValidateParams already requires an instance name)
        │
        ▼
ServeHTTP
  ├─ startupBlock + subscribeCaptcha + loadedCaptcha()==nil → 503 + WARN crowdsec bouncer backend missing
  └─ handleRemediationServeHTTP
        ├─ nil / !Valid / not captcha kind → BAN, no WARN
        └─ Valid client → captcha routing
```

Subscribe is constructor-only: `plugin.go` `subscribeCaptcha := config.BouncerEnabled && config.CaptchaInstanceName != ""`, then `reclaim.Watch`. Bounce-only `bouncer.New` does not build a local client.

```
  bouncing + name set --Watch alias:captcha:N--> captchaBound (Load)
  bouncing, name empty --no Watch--------------> captchaBound always nil
```

| Unit | Path | Job |
| --- | --- | --- |
| Subscribe gate | `plugin.go` `New` | `subscribeCaptcha` = bounce on + non-empty `CaptchaInstanceName`. Read only; no new knob. |
| Bouncer | `pkg/bouncer/bouncer.go` | Per-router handler. `subscribeCaptcha` + `loadedCaptcha()`. Captcha kind with empty/invalid client bans. |
| Remediation owner | `pkg/bouncer/bouncer.go` `handleRemediationServeHTTP` | One owner for captcha-kind serve vs ban. This ticket’s WARN lives here, gated on `!subscribeCaptcha`. |
| Startup-block sibling | `pkg/bouncer/bouncer.go` `warnBackendMissing` | WARN `crowdsec bouncer backend missing` + 503 only when **subscribed** and still nil. Out of scope to change. |
| Failure-action gate | `pkg/configuration/configuration.go` `validateFailureAction` | `captcha` requires an instance name after owner-fill. Unsubscribed + failure-action `captcha` is rejected at `New`. |
| Client address | `pkg/ip.GetRemoteIP` → `clientRequest.remoteIP` | Already chosen before remediation. This WARN does not reconstruct it. |
| Live spec | `openspec/specs/core_plugin_middleware_bouncer` | Captcha verdict without a published client is a ban. No misconfiguration WARN today. |

### Call sites (bounded)

| Contract | Count | Roots searched |
| --- | --- | --- |
| `handleRemediationServeHTTP(` production | **7** (`passOrForcedCaptcha` 331; `remediateOrForcedCaptcha` 340, 345, 348; forced `b` 431; AppSec failure captcha 633, 649) | `pkg/bouncer/bouncer.go` |
| `remediateOrForcedCaptcha(` production | **3** (stream lookup 468; live/none lookup 503; LAPI failure-action captcha 513) | `pkg/bouncer/bouncer.go` |
| `subscribeCaptcha :=` | **1** (`plugin.go` 113) | `plugin.go` |
| `warnBackendMissing(` | **1** helper; **3** startup-block calls (lapi, appsec, captcha) | `pkg/bouncer/bouncer.go` |
| Captcha-kind tests | **12** `handleRemediationServeHTTP` in `zzz_captcha_routing_test.go`; constructor `captchaForceReq` tests **5**; forced-decision tests in `zzz_forced_decision_test.go` | `pkg/bouncer/**`, `zzz_constructor_test.go` |
| `validateFailureAction` | **2** (`BouncerLapiFailureAction`, `BouncerAppsecFailureAction`) | `pkg/configuration/configuration.go` |

### Outside facts

In-tree: `knowledge/devdocs/core_plugin_middleware.md` (Subscribe, Captcha Client, Failure action), `core_plugin_middleware_captcha-routing.md`, `core_plugin_middleware_forced-decision.md`, `core_plugin_middleware_instance-slots.md`. Research: `knowledge/research/ext_crowdsec_bouncers_failure-action/` (failure-action `captcha` is a backend-down enum, not this subscribe miss). No new vendor clone.

### Language deltas (consume; no packet write)

No hard gap. **Subscribe** / **Captcha Client** / **Failure action** / **Bouncer** already name the units. Ticket “unsubscribed” is `subscribeCaptcha == false` (bounce on, empty `CaptchaInstanceName`). Do not write packets this phase. Do not treat AppSec JSON `action: captcha` as this signal (`Failure action` _Avoid_).

## Decisions

- **Seam:** One WARN in `handleRemediationServeHTTP` when kind is captcha and `!b.subscribeCaptcha`, then the existing ban. Do not WARN on subscribed-unpublished or `!Valid`.
- **Identity owner:** `pkg/ip.GetRemoteIP` already owns the client address on `clientRequest`. This WARN is router subscription, not identity. Reuse `req.remoteIP` only if a later phase adds an `ip` attr. Do not re-parse `RemoteAddr` or Host.
- **Live contract:** `openspec/specs/core_plugin_middleware_bouncer` (Requirement: Captcha verdict without a published client is a ban). Propose adds the unsubscribed WARN there. Neighbors stay as-is: `core_plugin_middleware_captcha-routing`, `core_plugin_middleware_forced-decision`, `core_plugin_lapi_failure-action`, `core_plugin_appsec_failure-action`. Not `no live contract`.
- **Rejected:** WARN on every nil/`!Valid` client (would cover subscribed-unpublished; Out of scope). A `sync.Once` / per-binding counter (new mechanism; siblings warn every request). New public config keys. Legalize failure-action `captcha` without an instance name. Reconstruct a local captcha client on bounce-only. WARN on AppSec JSON `action: captcha` (`handleAppsecResponseServeHTTP` is a different owner).

## Open questions

- Q: Exact WARN message text?
  Rank: additive asked — new log line this change creates; Unknowns “Exact WARN message text”; Desired names a WARN that captcha could not be served due to a misconfiguration
  Decision: assumed — stem `crowdsec bouncer captcha unsubscribed`, same family as `crowdsec bouncer backend missing` / `crowdsec bouncer stream scopes missing`. Attrs `leg=captcha` and `instanceName` (empty when unsubscribed). Logger already carries `traefikName` from `bouncer.New`.
  By: explore

- Q: WARN once per binding or on every remediating request?
  Rank: additive asked — Unknowns “Whether WARN is once per binding or on every remediating request”
  Decision: assumed — every remediating request, matching `warnBackendMissing` and `ServeHTTP:forcedCaptchaSuperseded`. Do not add a Once field on Bouncer.
  By: explore

- Q: Is “signal” only LAPI captcha kind, or also forced header `c` and captcha failure-action?
  Rank: bounded asked — Unknowns names those three; they already share `handleRemediationServeHTTP`; **7** production call sites, roots `pkg/bouncer/bouncer.go`, `plugin.go`, `pkg/configuration/configuration.go`
  Decision: assumed — all captcha-kind remediations that reach `handleRemediationServeHTTP` (LAPI/remap kind `c`, forced `c`, LAPI/AppSec failure-action `captcha`). Failure-action `captcha` without an instance name stays illegal at `ValidateParams` (Out of scope). AppSec JSON `action: captcha` stays on `handleAppsecResponseServeHTTP` and does not get this WARN.
  By: explore

- Q: Who already owns the client address if this WARN logs identity?
  Rank: additive incidental — GetRemoteIP is unchanged; requirement does not name an identity reshape
  Decision: assumed — owner is `pkg/ip.GetRemoteIP` / `clientRequest.remoteIP` (devdocs `core_plugin_middleware.md`). This WARN does not emit `ip` (sibling is `warnBackendMissing`, not `forcedCaptchaSuperseded`). Host / tenant / trust hop are not reconstructed.
  By: explore

- Q: Does subscribed-unpublished (startup-block off) or `!Valid` also WARN?
  Rank: additive asked — Out of scope “Changing subscribed-but-unpublished behavior”; Tensions “WARN is the gap; treating unpublished-subscribed the same as unsubscribed is not asked”
  Decision: resolved — no. Gate on `!subscribeCaptcha` only. Subscribed + nil + `startupBlock` stays 503 + `crowdsec bouncer backend missing`. Subscribed + nil/`!Valid` + block off stays silent ban.
  By: explore
