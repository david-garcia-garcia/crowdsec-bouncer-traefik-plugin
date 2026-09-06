# Captcha handler

## Language

**Captcha handler**:
The `pkg/captcha.Client` that renders the captcha HTML page, POSTs to the provider siteverify endpoint, and writes the grace-period cache entry after a successful solve. Lives on Bouncer, not the LAPI Client.
_Avoid_: AppSec challenge relay, AppSec JSON `action: captcha`, LAPI captcha remediation enum

**Grace period**:
The TTL window after a successful siteverify during which `Check` treats the client IP as captcha-solved. Stored as `<remoteIP>_captcha` with value `d` (`cache.CaptchaDoneValue`) on the LAPI Client's isolated cache.
_Avoid_: session, cookie, solve token

**Retryable verify failure**:
A provider transport error, non-JSON response, or JSON decode failure wrapped with `ErrRetryableVerify`. ServeHTTP re-renders captcha (200), same UX as `success: false`.
_Avoid_: bare 400 on provider outage

## Overview

Bouncer calls `Check` before remediation, then `ServeHTTP` on captcha decisions or failure actions. The handler receives bouncer-resolved `remoteIP`; do not re-parse headers for siteverify `remoteip`.

## How to use

- Construct with `Client.New` on Bouncer init. When `CaptchaProvider != ""`, `CaptchaFilePath` must be non-empty and loadable (`ValidateParams` and `New` both fail on missing template).
- `Validate(r, remoteIP)` POSTs `secret`, `response`, and `remoteip` to the provider validate URL.
- After successful verify, call `cacheClient.Set(remoteIP+"_captcha", cache.CaptchaDoneValue, gracePeriodSeconds)` and check the error before HTTP 302.
- On grace cache write failure: log at Error, re-render captcha (200); do not redirect.
- On `errors.Is(err, ErrRetryableVerify)`: log and re-render captcha (200).
- `Check(remoteIP)` reads the grace key; ignore Get errors (miss → not solved).

## Pattern snippet

```go
valid, err := c.Validate(r, remoteIP)
if errors.Is(err, ErrRetryableVerify) {
	c.renderCaptcha(rw, r)
	return
}
if valid {
	if err := c.cacheClient.Set(remoteIP+"_captcha", cache.CaptchaDoneValue, c.gracePeriodSeconds); err != nil {
		c.log.Error("grace cache write failed: " + err.Error())
		c.renderCaptcha(rw, r)
		return
	}
	http.Redirect(rw, r, r.URL.String(), http.StatusFound)
	return
}
c.renderCaptcha(rw, r)
```

## Key files

- `pkg/captcha/captcha.go`
- `pkg/bouncer/bouncer.go`
- `pkg/configuration/configuration.go`

## Gotchas

- AppSec JSON `action: captcha` is relay HTML, not this handler (`core_plugin_appsec`).
- Empty `CaptchaFilePath` with a provider set is a startup validation error (breaking vs older optional path).
- Memory cache `Set` always returns nil; only Redis-backed writes can fail observably.
