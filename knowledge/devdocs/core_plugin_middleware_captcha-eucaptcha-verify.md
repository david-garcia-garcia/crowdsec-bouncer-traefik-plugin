# Eucaptcha verify

## Language

**Eucaptcha verify**:
The EU CAPTCHA HTTP reply to a solver-token check (`eucaptchaVerifier.Pass` POST to `https://api.eu-captcha.eu/v1/verify`).
_Avoid_: siteverify, assessments, `/verify-credentials`

**train**:
JSON boolean or null on a 200 verify body. `true` means verification was skipped (Pass-false). `false` or null with `success` true is Pass-true.
_Avoid_: treating `success` alone as pass

## Overview

`eucaptcha` pairs the eucaptcha verifier in `Client.New`. `Validate` calls `Pass` only after a non-empty token. `client_ip` is `clientRequest.remoteIP` after GetRemoteIP (`core_plugin_ip`). `client_user_agent` is `r.UserAgent()`. Siteverify encoding stays on `core_plugin_middleware_captcha-siteverify`. Assessments stay on `core_plugin_middleware_captcha-assessments`. Gate cookie format stays on `core_plugin_middleware_captcha-gate`. Widget pairing stays on `core_plugin_middleware_captcha-widget`.

## How to use

- POST JSON to `https://api.eu-captcha.eu/v1/verify` on the captcha `http.Client` (`captchaSiteverifyHTTPTimeoutSeconds`).
- Send `Content-Type: application/json`. Do not log the secret.
- Body always has `sitekey`, `secret`, `client_ip`, `client_token`, and `client_user_agent`.
- Reuse `Validate`'s `remoteIP` and `r.UserAgent()`. Do not parse `X-Forwarded-For`, `X-Real-Ip`, `X-Client-IP`, or `RemoteAddr`. Do not send the LAPI plugin User-Agent.
- Empty `remoteIP` is Pass-false with no vendor POST. Empty `userAgent` is still POSTed as `""`.
- Pass only when HTTP 200 JSON has `success` true and `train` is JSON false or null (`*bool` nil counts as false-or-null). `train` true is Pass-false. `success` false is Pass-false.
- Non-2xx or undecodable JSON is the error return, not reject. Cap the body the same way assessments does (64KiB).
- Do not add a `/verify-credentials` startup probe.

## Pattern snippet

```go
req.Header.Set("Content-Type", "application/json")
```

## Key files

- `pkg/captcha/eucaptcha.go`
- `pkg/captcha/captcha.go` (`New`, `Validate`)

## Gotchas

- Official `success` is true when `train` is true (wrong credentials / protection off). Mint only when `train` is false or null.
- An omitted `train` key and JSON null both decode as nil on `*bool`.
- Empty token stays `None` on `Validate`; do not POST even though the vendor says always send `client_token`.
