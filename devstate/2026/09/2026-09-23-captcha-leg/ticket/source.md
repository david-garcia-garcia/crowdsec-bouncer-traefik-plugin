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
