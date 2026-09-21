# Captcha siteverify

## Language

**Captcha siteverify**:
The provider HTTP response to a solver-token check (`Client.Validate` POST to the provider validate URL).
_Avoid_: inbound captcha form Content-Type, captcha gate cookie, captcha request routing

**Siteverify JSON**:
A captcha siteverify whose `Content-Type` media type before parameters equals `application/json` case-insensitively.
_Avoid_: lowercase `application/json` prefix, `application/jsonp`, treating a missing Content-Type as JSON

## Overview

`Client.Validate(r, remoteIP)` posts `secret` and `response` to the provider validate URL, plus `remoteip` when that address is non-empty (`clientRequest.remoteIP` after GetRemoteIP). Do not parse forwarded headers in captcha. Encode from `Client.validateBody` (custom-only). Classify the provider body as JSON from the response media type, then decode `success`. Transport and JSON-decode errors stay `(false, err)`; `ServeHTTP` logs and re-renders the 200 challenge. Cookie format stays on `core_plugin_middleware_captcha-gate`. Routing after the cookie stays on `core_plugin_middleware_captcha-routing`. Config tokens stay on `core_plugin_middleware_config-validation`.

## How to use

- Thread `ServeHTTP`'s `remoteIP` into `Validate(r, remoteIP)`. Include `remoteip` with `secret` and `response` on both encodings when `remoteIP` is non-empty. Do not re-parse `X-Forwarded-For`.
- Encode the provider request from `Client.validateBody` (custom-only, filled in `New` from `CaptchaCustomValidateBody`). `json` POSTs `application/json` `{"secret","response"}` (and `remoteip` when given). Empty or `form`, and every built-in, keep `PostForm`.
- Do not put the encoding on `infoProviders`. Do not invent `remoteip` when `Validate` is given an empty client address.
- Classify with `mime.ParseMediaType` on the siteverify `Content-Type`. Compare the returned type token to `application/json`.
- Do not match the raw header with `strings.HasPrefix`.
- Parse error, missing header, or a different type: log `responseType:noJson` and return `(false, nil)`. That pair is not an error; `ServeHTTP` writes the 200 challenge and does not mint the cookie.
- Transport (`postSiteverify`) or JSON `Decode` error: return `(false, err)`. `ServeHTTP` logs and writes the 200 challenge. Do not write HTTP 400.
- Siteverify JSON plus decoded `success` true: `ServeHTTP` sets `crowdsec_captcha_gate` and 302 to the request URL. Same outcome as lowercase `application/json`.
- Do not inspect siteverify HTTP status in this unit.

## Key files

- `pkg/captcha/captcha.go` (`Validate`)
- `pkg/captcha/gate.go`

## Gotchas

- `application/json; charset=utf-8` is Siteverify JSON; `application/jsonp` is not.
- A JSON body with no `Content-Type` stays `(false, nil)`.
- A down provider or a non-JSON body with JSON Content-Type is a 200 challenge, not a bare 400.
- Built-in leftover `json` is rejected at `ValidateParams`, not ignored at Validate.
- Official Cap Standalone request is JSON `secret`+`response` (`knowledge/research/ext_capjs_standalone_siteverify/`). Wicketkeeper omit stays urlencoded.
