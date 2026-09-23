# Captcha as a named instance

Date: 2026-09-23.

Captcha becomes a third leg, beside LAPI and AppSec. One middleware owns the captcha client and publishes it under a name. Other routers subscribe to that name and do not copy the captcha settings.

## Knobs

Same axes as the other legs.

| Knob | Role |
| --- | --- |
| `captchaEnabled` | This middleware owns the captcha client and publishes the name. |
| `captchaInstanceName` | Name of the captcha slot. LAPI, AppSec, and captcha each have their own name table, so each may be called `shared`. |
| `enabled` | This middleware bounces. It subscribes to `captchaInstanceName` when that name is set. |

An empty instance name is filled with this middleware's Traefik name only when `captchaEnabled` is true. A subscriber sets the name and leaves `captchaEnabled` false. One middleware may both own and bounce. A holder with `enabled: false` can own the client; Traefik still needs a router so the plugin starts. `New` does not wait for the owner to exist.

A subscriber that also sets captcha keys is ignored. Those keys are read on the owner.

## What the instance owns

Every captcha setting:

- Provider, site key, secret key, and their files
- Siteverify timeout, custom validate URL, custom validate body
- Custom JS URL, CSS class, response field, challenge URL
- Captcha template path
- Gate secret and file, bind-IP, grace period

Subscribers of one name share that page, that verifier, those widget paths, and that grace. A solve on one router counts on the others: the grace cookie is host-wide. A different page or a stricter grace is a second captcha instance.

Two captcha instances on the same host still use one cookie name (`crowdsec_captcha_gate`, path `/`). A later solve overwrites the earlier cookie. Leaving that as-is for this cut.

## What stays on the router

Bounce policy stays per router. Failure actions stay here. `crowdsecLapiFailureAction: captcha` (and the AppSec twin) means "use the captcha instance this router subscribed to." That value is legal only when this router has a captcha instance name.

The remediation header stays on the router. The challenge page and the solved redirect use this router's header, not a header copied from the owner.

## When captcha is missing

`captchaEnabled` requires a provider, both keys, a gate secret, and a template that loads. A subscriber is not checked for those.

A captcha verdict on a router that did not subscribe is a ban.

While startup block is on, a subscribed captcha name that is not published yet is **503** for every request on that router, same as a missing LAPI or AppSec client. With startup block off, requests continue, and a captcha verdict with no published client is a ban.


## Current (code)

- Captcha is not a named reclaim leg. `plugin.go` `New` opens, claims, and `reclaim.Watch`es LAPI and AppSec only. Bounce subscribe is `BouncerEnabled` plus an LAPI or AppSec instance name.
- `captchaEnabled` — not found.
- `captchaInstanceName` — not found.
- Spec `enabled` (bounce) is `bouncerEnabled` on dest: `pkg/configuration/configuration.go`.
- Empty owner name filled with the Traefik name: LAPI does this when `LapiEnabled` in `pkg/lapi/client.go`. Captcha fill — not found.
- Holder with bounce off can still own LAPI/AppSec: `pkg/configuration/configuration.go` `validateLegOpenVsSubscribe`. Captcha owner-without-bounce — not found.
- `New` does not wait for a published LAPI/AppSec owner: `plugin.go` `reclaim.Watch`. Captcha watch — not found.
- Subscriber captcha keys ignored — not found. `pkg/bouncer/bouncer.go` `New` always builds `captcha.Client` from this router's `BouncerCaptcha*` fields.
- Spec `crowdsecLapiFailureAction` is `bouncerLapiFailureAction` on dest: `pkg/configuration/configuration.go`. The AppSec twin is `bouncerAppsecFailureAction`. `captcha` is legal when `BouncerCaptchaProvider` is set, not when a captcha instance name is set (`validateFailureAction`).
- Remediation header stays on the router: `pkg/bouncer/bouncer.go` `BouncerRemediationHeadersCustomName`.
- Owner-style captcha checks (provider, keys, gate secret, loadable template) run when `BouncerCaptchaProvider` is set: `pkg/configuration/configuration.go`. There is no subscriber skip.
- Captcha verdict without a captcha subscribe — not found (no captcha subscribe flag). `pkg/bouncer/bouncer.go` remediates captcha with this router's client.
- Startup-block 503 for an unpublished subscribed name: `pkg/bouncer/bouncer.go` checks LAPI and AppSec only.
- Cookie name `crowdsec_captcha_gate` path `/`: `pkg/captcha/gate.go`. One name for every captcha client.

## Affected

- `plugin.go` — own, claim, and watch; LAPI and AppSec only
- `pkg/configuration/configuration.go` — public knobs and validation
- `pkg/bouncer/bouncer.go` — per-router captcha client and startup-block 503
- `pkg/lapi/client.go` — owner empty-name fill
- `pkg/captcha/gate.go` — shared grace cookie

## Out of scope

- Renaming dest's existing `lapi*` / `appsec*` / `bouncer*` public keys back to the spec's `enabled` / `crowdsecLapiFailureAction` spellings.
- Changing the shared `crowdsec_captcha_gate` cookie name or path (spec leaves that as-is).
- A second cookie namespace so two captcha instances on one host do not overwrite each other.

## Unknowns

- Whether `bouncer.New` should keep constructing a local captcha client after captcha is a named leg, or fail closed when the owner is missing and startup block is off.
- Blast radius of sharing one captcha client across routers (siteverify HTTP client, template, grace clock).
- How a captcha verdict with no published client is remediating today when `BouncerCaptchaProvider` is empty.
- Whether AppSec's empty-name fill (`pkg/appsec/client.go`) is the pattern captcha should copy, or LAPI's `enabled && empty` fill.

## Tensions

- Spec knob `enabled` vs dest public key `bouncerEnabled` (`pkg/configuration/configuration.go`). Desired is the bounce-and-subscribe axis; dest already named it `bouncerEnabled`.
- Spec `crowdsecLapiFailureAction` (and the AppSec twin) vs dest `bouncerLapiFailureAction` / `bouncerAppsecFailureAction`. Desired meaning is unchanged: `captcha` uses the captcha instance this router subscribed to. Dest already renamed the keys in the PR 137 squash.
- Spec `captchaEnabled` / `captchaInstanceName` have no dest keys. Dest captcha settings are per-router `bouncerCaptcha*` on the same `Config`, not a third named instance.
- Spec: `captcha` failure action is legal only with a captcha instance name. Dest: legal only with `BouncerCaptchaProvider` (`validateFailureAction`).