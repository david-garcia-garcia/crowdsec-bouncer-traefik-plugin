# Captcha siteverify

## Language

**Captcha siteverify**:
The provider HTTP response to a solver-token check (`Client.Validate` POST to the provider validate URL).
_Avoid_: inbound captcha form Content-Type, captcha gate cookie, captcha request routing

**Siteverify JSON**:
A captcha siteverify whose `Content-Type` media type before parameters equals `application/json` case-insensitively.
_Avoid_: lowercase `application/json` prefix, `application/jsonp`, treating a missing Content-Type as JSON

## Overview

`Client.Validate` posts `secret`, `response`, and `remoteip`. `remoteip` is the `remoteIP` already passed into `ServeHTTP` (`clientRequest.remoteIP` after GetRemoteIP). Do not parse forwarded headers in captcha. Classify the provider body as JSON from the response media type, then decode `success`. Transport and JSON-decode errors stay `(false, err)`; `ServeHTTP` logs and re-renders the 200 challenge. Cookie format stays on `core_plugin_middleware_captcha-gate`. Routing after the cookie stays on `core_plugin_middleware_captcha-routing`.

## How to use

- Thread `ServeHTTP`'s `remoteIP` into `Validate(r, remoteIP)`. `Add` form `remoteip` with `secret` and `response`. Do not re-parse `X-Forwarded-For`.
- Classify with `mime.ParseMediaType` on the siteverify `Content-Type`. Compare the returned type token to `application/json`.
- Do not match the raw header with `strings.HasPrefix`.
- Parse error, missing header, or a different type: log `responseType:noJson` and return `(false, nil)`. That pair is not an error; `ServeHTTP` writes the 200 challenge and does not mint the cookie.
- Transport (`PostForm`) or JSON `Decode` error: return `(false, err)`. `ServeHTTP` logs and writes the 200 challenge. Do not write HTTP 400.
- Siteverify JSON plus decoded `success` true: `ServeHTTP` sets `crowdsec_captcha_gate` and 302 to the request URL. Same outcome as lowercase `application/json`.
- Do not inspect siteverify HTTP status in this unit.

## Key files

- `pkg/captcha/captcha.go` (`Validate`)
- `pkg/captcha/gate.go`

## Gotchas

- `application/json; charset=utf-8` is Siteverify JSON; `application/jsonp` is not.
- A JSON body with no `Content-Type` stays `(false, nil)`.
- A down provider or a non-JSON body with JSON Content-Type is a 200 challenge, not a bare 400.
