# Captcha siteverify

## Language

**Captcha siteverify**:
The provider HTTP response to a solver-token check (`Client.Validate` POST to the provider validate URL).
_Avoid_: inbound captcha form Content-Type, captcha gate cookie, captcha request routing

**Siteverify JSON**:
A captcha siteverify whose `Content-Type` media type before parameters equals `application/json` case-insensitively.
_Avoid_: lowercase `application/json` prefix, `application/jsonp`, treating a missing Content-Type as JSON

## Overview

`Client.Validate` POSTs `secret` and `response` to the provider validate URL, classifies the reply as JSON from the response media type, then decodes `success`. Cookie format stays on `core_plugin_middleware_captcha-gate`. Routing after the cookie stays on `core_plugin_middleware_captcha-routing`. Config tokens stay on `core_plugin_middleware_config-validation`.

## How to use

- Encode the provider request from `Client.validateBody` (custom-only, filled in `New` from `CaptchaCustomValidateBody`). `json` POSTs `application/json` `{"secret","response"}` on the dest `httpClient`. Empty or `form`, and every built-in, keep `PostForm`.
- Do not put the encoding on `infoProviders`. Do not invent `remoteip` unless `Validate` is given a non-empty client address (`GetRemoteIP` / `clientRequest.remoteIP` on `ServeHTTP`). Dest today is `Validate(r)` only.
- Classify with `mime.ParseMediaType` on the siteverify `Content-Type`. Compare the returned type token to `application/json`.
- Do not match the raw header with `strings.HasPrefix`.
- Parse error, missing header, or a different type: log `responseType:noJson` and return `(false, nil)`. That pair is not an error; `ServeHTTP` writes the 200 challenge and does not mint the cookie.
- Siteverify JSON plus decoded `success` true: `ServeHTTP` sets `crowdsec_captcha_gate` and 302 to the request URL. Same outcome as lowercase `application/json`.
- Do not inspect siteverify HTTP status in this unit.

## Key files

- `pkg/captcha/captcha.go` (`Validate`)
- `pkg/captcha/gate.go`

## Gotchas

- `application/json; charset=utf-8` is Siteverify JSON; `application/jsonp` is not.
- A JSON body with no `Content-Type` stays `(false, nil)`.
- Built-in leftover `json` is rejected at `ValidateParams`, not ignored at Validate.
- Official Cap Standalone request is JSON `secret`+`response` (`knowledge/research/ext_capjs_standalone_siteverify/`). Wicketkeeper omit stays urlencoded.
