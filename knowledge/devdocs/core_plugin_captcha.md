# Captcha client

## Language

**Captcha Client**:
The per-Bouncer owner of captcha provider URLs, grace `Check`, HTML/validate `ServeHTTP`, and custom resource path match (`pkg/captcha`). Not AppSec challenge relay and not LAPI `crowdsecLapiFailureAction: captcha`.
_Avoid_: AppSec JSON `action: captcha`, LAPI failure action, Bouncer

**Custom captcha resource**:
A request whose path equals the path of `CaptchaCustomJsURL` or `CaptchaCustomChallengeURL`. On captcha remediation it reaches origin; on ban it does not.
_Avoid_: captcha HTML page, `CaptchaCustomValidateURL`, CDN widget URL

## Overview

Custom captcha widgets load JS and a challenge from origin paths. The Captcha Client parses those config URLs once at `New` and answers whether the request path is a custom resource. The Bouncer asks that owner, then uses `handleNextServeHTTP`.

## How to use

- Set `captchaProvider=custom` plus the existing custom JS, validate, key, and response fields.
- Set optional `captchaCustomChallengeUrl` when the widget fetches a same-host challenge (for example `/v0/challenge`). Empty means no challenge pass-through.
- Match is exact `url.Path` of each configured value vs `req.URL.Path`. Host and query do not participate. Absolute JS URLs still match the browser path.
- On captcha kind, a custom resource (any method, including HEAD) goes to `handleNextServeHTTP`. Ban kind never passes those paths.
- Put `ChallengeURL` in the captcha template map. Default `captcha.html` may omit it. Client address stays `clientRequest.remoteIP`.

## Pattern snippet

```go
if b.captchaClient.IsCustomResourceRequest(req.Request) {
	b.handleNextServeHTTP(rw, req)
	return
}
```

## Key files

- `pkg/captcha/captcha.go`
- `pkg/bouncer/bouncer.go`
- `pkg/configuration/configuration.go`

## Gotchas

- Non-custom providers must not treat CDN JS URLs as pass-through resources.
- Unmatched captcha HEAD still falls through to ban.
- Pass-through uses the existing pass path; AppSec still runs if enabled.
- Do not parse `RemoteAddr` for this match.
