# Captcha remediation

## Language

**Captcha Client**:
The per-router owner of captcha HTML, provider verify, and captcha grace (`pkg/captcha` on Bouncer). Not AppSec JSON `action: captcha`. Not the LAPI Client.
_Avoid_: AppSec challenge, CrowdsecConnection, process singleton

**Captcha grace**:
Cache value `remoteIP+"_captcha"` = `CaptchaDoneValue` after a successful provider verify. Lookup uses `clientRequest.remoteIP` already chosen by `GetRemoteIP`.
_Avoid_: re-parsing `RemoteAddr`, a second IP string

**Captcha form POST**:
A POST that carries the configured provider response field (`h-captcha-response`, `g-recaptcha-response`, `cf-turnstile-response`, or the custom response field).
_Avoid_: treating every POST during grace as captcha; keying only off the config name `captchaCustomResponse`

**Solved redirect**:
HTTP 302 Found to the request URL after a successful verify or an already-solved captcha form POST, with remediation header `solved-captcha` when that header is configured.
_Avoid_: forwarding that POST to origin, `303`, re-calling the provider

## Overview

Bouncer owns when captcha remediation applies. Captcha Client owns the field name, the first-verify redirect, and whether a request is a captcha form POST. After grace, ordinary GET/POST still take the pass path; a captcha form POST takes the solved redirect so GET-only origins do not see POST.

## How to use

- Put Captcha Client on Bouncer (`captcha.Client.New`). Do not put it on LAPI Client identity.
- Grace lookup: `Check(req.remoteIP)`. Do not parse `RemoteAddr` again.
- After `Check` is true, if `IsCaptchaFormPost(req.Request)` then `WriteSolvedRedirect` — do not `handleNextServeHTTP` (AppSec/origin never see that POST).
- Ordinary POST during grace still goes to `handleNextServeHTTP`. `IsCaptchaFormPost` restores Body when it is not a captcha form. Do not `FormValue` then forward.
- Peek at most `captchaFormMaxBytes` (64KiB). Larger POSTs are origin forms.
- First successful verify: `Set` grace then the same `WriteSolvedRedirect`. Do not duplicate the 302 in bouncer.

## Pattern snippet

```go
if b.captchaClient.Check(req.remoteIP) {
	if b.captchaClient.IsCaptchaFormPost(req.Request) {
		b.captchaClient.WriteSolvedRedirect(rw, req.Request)
		return
	}
	b.handleNextServeHTTP(rw, req)
	return
}
```

## Key files

- `pkg/captcha/captcha.go`
- `pkg/bouncer/bouncer.go`
- `captcha.html`

## Gotchas

- Bundled `captcha.html` POSTs to the current URL (empty form `action`). There is no dedicated captcha path.
- Do not re-verify with the provider on the already-solved path (tokens are often one-time).
- Do not change `captcha.html` to fix duplicate-tab 405; intercept on the grace path instead.
