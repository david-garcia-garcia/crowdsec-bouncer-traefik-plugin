# Delivery

## Motivation

A bouncing router that never subscribed to captcha (bounce on, empty `CaptchaInstanceName`) can still receive captcha kind: LAPI remediates captcha, a forced decision header `c`, or a captcha failure-action that already reached remediation. That request already becomes a ban. Subscribe is constructor-only: only bounce plus a non-empty instance name watches captcha; bounce-only construction never builds a local client.

When captcha kind arrives on an unsubscribed router, the remediating handler already degrades to ban because the loaded client is nil. It does not tell the operator that this router never subscribed. The 403 looks like a normal CrowdSec ban or a subscribed-unpublished degrade. Startup-block already warns `crowdsec bouncer backend missing` only when the router did subscribe and the client is still nil.

Left alone, operators cannot tell a wiring miss from a real ban. They keep a bouncing router without a captcha instance and treat captcha remediations as ordinary bans, with no log that a challenge could not be served because the router never subscribed.

Priority: P2 — real operator pain, with a workaround or limited blast radius

## Implementation

The remediating handler now checks captcha kind and `subscribeCaptcha` first. When the router never subscribed, it emits WARN `crowdsec bouncer captcha unsubscribed` with `leg=captcha` and `instanceName` (empty when unsubscribed), then the existing ban. The WARN fires on every remediating request that hits that branch: LAPI captcha kind, forced header `c`, and captcha failure-action that already reached this owner. It does not emit `ip`. Subscribed-unpublished and invalid clients stay on the dest ban path with no this WARN. Startup-block subscribed-nil stays 503 plus `crowdsec bouncer backend missing`. No new public config keys. Failure-action `captcha` without an instance name stays illegal at validate.

## What this changes
**Operators.** Every remediating captcha-kind request on an unsubscribed bouncing router now logs WARN `crowdsec bouncer captcha unsubscribed` (`leg=captcha`, empty `instanceName`); the response stays a 403 ban.
**Admin users.** None.
**Developers.** Unsubscribed captcha kind must WARN then ban; this stem must not fire when subscribed, including unpublished or invalid client, and must not carry `ip`.
**End users.** None.
