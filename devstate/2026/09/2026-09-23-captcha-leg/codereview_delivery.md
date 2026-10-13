# Delivery

## Motivation

Operators already share one LAPI client or one AppSec client across routers: one middleware Opens and publishes a name; bouncing routers Watch that name and keep bounce policy on the router. Captcha was not in that table.

Each bouncing middleware built its own siteverify client, template, and gate from that router’s `bouncerCaptcha*` copy. There was no `captchaEnabled` or `captchaInstanceName`. `bouncer.New` always constructed a local client, so leftover subscriber keys still owned captcha. Failure action `captcha` was legal when `bouncerCaptchaProvider` was set, not when the router had a captcha instance name. Startup-block 503 covered a missing LAPI or AppSec subscribe only. A holder with bounce off could not publish captcha for others.

Operators who wanted one page, one verifier, and one grace across several routers had to duplicate every captcha key. Those copies drift (different grace, different template, different siteverify timeout). A change to the challenge page meant touching every bouncing middleware. The share-one-client model they already use for LAPI and AppSec stopped at captcha.

Priority: P2 — operator pain with a workaround

## Implementation

Captcha is a third reclaim group beside LAPI and AppSec. The constructor Prepares, Opens, claims, and Watches group `captcha` the same way: `captchaEnabled` owns; `bouncerEnabled` plus a non-empty `captchaInstanceName` bounces. An omitted name fills to the Traefik name only when owned. Default own flag is false; a set provider does not own.

The owner Opens the siteverify client, template, and gate from dest `bouncerCaptcha*` keys. The ownership key is the middleware name plus those instance knobs; slot name, bounce, failure action, remediation header, and startup-block stay off it. Subscribers Watch only. Bounce-only `New` does not construct a local client. Leftover subscriber keys are ignored; owner-style checks run only when `captchaEnabled`.

The Bouncer Stores the published pointer and Loads it on the request path. The remediation header stays on the router and is passed into the challenge page and the solved redirect so a subscriber does not inherit the owner’s header. Startup block on returns 503 for an unpublished subscribed captcha name. Startup block off continues; a captcha verdict with no published client is a ban. Failure action `captcha` is legal when the instance name is ready after owner-fill. In-repo examples and e2e set `captchaEnabled: true` on captcha-serving routes.

## What this changes
**Operators.** YAML that only sets `bouncerCaptchaProvider` no longer owns or serves captcha; set `captchaEnabled: true` on the owner (empty `captchaInstanceName` fills to the Traefik name) and subscribe other routers to that name. Leftover subscriber `bouncerCaptcha*` is ignored. `captcha` on `bouncerLapiFailureAction` / `bouncerAppsecFailureAction` requires that router’s instance name after fill. An unpublished subscribed name is 503 when startup block is on.
**Admin users.** None.
**Developers.** Captcha is a third reclaim value (`Prepare` / `Open` / `Watch`); `bouncer.New` takes `subscribeCaptcha` and Loads the published client. `Client.New`, `ServeHTTP`, and `WriteSolvedRedirect` take the remediation header at the call site, not on the Client. Failure action `captcha` requires an instance name after fill.
**End users.** None.
