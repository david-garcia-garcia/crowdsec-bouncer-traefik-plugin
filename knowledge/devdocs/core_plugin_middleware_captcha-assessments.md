# Assessment

## Language

**Assessment**:
The Cloud reCAPTCHA Enterprise HTTP reply to a solver-token check (`assessmentsVerifier.Pass` POST to `…/projects/{project}/assessments`).
_Avoid_: siteverify, `success` bit, Google client library

**Assessments pass order**:
`tokenProperties.valid`, then action when configured (case-insensitive), then `riskAnalysis.score` when a minimum is set.
_Avoid_: score-first, treating a Google error envelope as reject

## Overview

`recaptcha-enterprise` pairs the assessments verifier in `Client.New`. `Validate` calls `Pass` only after a non-empty token. Siteverify encoding stays on `core_plugin_middleware_captcha-siteverify`. Gate cookie format stays on `core_plugin_middleware_captcha-gate`. `event.userIpAddress` is `clientRequest.remoteIP` after GetRemoteIP (`core_plugin_ip`).

## How to use

- POST JSON to `https://recaptchaenterprise.googleapis.com/v1/projects/{project}/assessments` on the captcha `http.Client` (`captchaSiteverifyHTTPTimeoutSeconds`).
- Send the Cloud API key as `X-Goog-Api-Key`. Do not put it on the query string. Do not log it.
- Body always has `event.token` and `event.siteKey`. Add `event.userIpAddress` only when `remoteIP` is non-empty. Add `event.expectedAction` only when action is non-empty after trim.
- Do not parse `X-Forwarded-For`, `X-Real-Ip`, or `RemoteAddr` in captcha.
- Pass only when, in order: `tokenProperties.valid` is true; configured action matches `tokenProperties.action` case-insensitively; configured minimum is `<= riskAnalysis.score`. Checkbox with no action and no minimum passes on `valid` alone.
- Non-2xx, empty/non-JSON body, or a Google error envelope without `tokenProperties` is the error return, not reject. `valid` false on a 2xx Assessment is reject.
- Do not add a Google client library.

## Pattern snippet

```go
req.Header.Set("Content-Type", "application/json")
req.Header.Set("X-Goog-Api-Key", apiKey)
```

## Key files

- `pkg/captcha/assessments.go`
- `pkg/captcha/enterprise.go`
- `pkg/captcha/captcha.go` (`Validate`)

## Gotchas

- A missing `tokenProperties` object is Error, even on HTTP 2xx.
- Score compare is `score < minScore` reject; equal to the minimum passes.
- Empty `remoteIP` omits `userIpAddress`; do not invent the field.
