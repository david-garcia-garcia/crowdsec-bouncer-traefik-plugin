# Plugin captcha

## Language

**Custom validate body**:
The operator enum (`form` | `json`) that selects how `pkg/captcha` posts `secret` and `response` to a custom siteverify URL. Empty is `form`. Built-in providers always form.
_Avoid_: MIME Content-Type string, auto-detect from URL, extra body/header maps

## Overview

Captcha live on the per-router Bouncer. Custom providers already set JS URL, validate URL, widget class, and the browser form field. CapJS Standalone needs JSON siteverify; Wicketkeeper-style setups keep urlencoded form.

## How to use

- Put captcha on Bouncer (`captcha.Client.New` from `bouncer.New`). Do not put it on LAPI or AppSec clients.
- Read the solved token with `CaptchaCustomResponse` from the browser POST. Outbound siteverify key is always `response`.
- For CapJS, set `captchaCustomValidateBody: json`, `captchaCustomResponse: cap-token`, and put the site key in `CaptchaCustomValidateURL` (`https://<instance>/<site_key>/siteverify`).
- Reuse `pkg/ip.GetRemoteIP` for grace-cache `remoteIP`. Do not reconstruct the client address in captcha. Do not send `remoteip` on siteverify.
- Decode provider JSON `success` only. Drain and close the siteverify body.

## Key files

- `pkg/captcha/captcha.go` — page, grace cache, siteverify
- `pkg/configuration/configuration.go` — `CaptchaCustom*` knobs
- `pkg/bouncer/bouncer.go` — wires `captcha.Client`

## Gotchas

- Default empty/`form` is required so existing custom form providers keep working.
- CapJS widget field is `cap-token`, not `h-captcha-response`.
