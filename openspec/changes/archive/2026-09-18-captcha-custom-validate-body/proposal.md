## Why

Cap Standalone / CapJS siteverify wants `POST application/json` `{"secret","response"}`. Dest `Validate` always `PostForm`s urlencoded `secret`+`response`. `captchaCustomResponse` already names the browser field (`cap-token`); the second-hop body encoding is not configurable, so a custom Cap instance cannot verify tokens.

## What Changes

- Add optional `captchaCustomValidateBody` / `CaptchaCustomValidateBody`: after trim, `""` or `"form"` keeps today's `PostForm`; `"json"` POSTs `application/json` with `secret` and `response`. Same dest `httpClient`. Do not split timeouts.
- Knob is custom-only. Built-in hcaptcha / recaptcha / turnstile always `PostForm`. `ValidateParams` rejects `"json"` when the provider is not `custom`. Rejects unknown values (including `JSON` / `Form`) for any provider. Built-in leftover `""` / `"form"` is ignored.
- Default omit keeps Wicketkeeper `examples/custom-captcha` on urlencoded. Do not retarget that example.
- README documents the knob and a CapJS **custom** example (validate URL + `cap-token` + `json`). No `trycap` provider, no `captchaTrycapInstanceUrl`, no `<cap-widget>` template branch.
- Do not invent `remoteip` on current dest (`Validate(r)` has no IP). Implement syncs `origin/master` and absorbs only if dest then threads `remoteIP` into `Validate`; then include `remoteip` on both encodings when non-empty. Owner is `pkg/ip.GetRemoteIP` / `clientRequest.remoteIP`, already on `ServeHTTP`. Do not re-parse forwarded headers in captcha.
- Keep dest siteverify reply `mime.ParseMediaType` + `success`, gate cookie + 302, void `cache.Set`.
- Store the encoding on `Client` (custom-only, sibling of `challengeURL`), not `infoProviders`. `bouncer.New` passes the config string into `Client.New`.
- **Not BREAKING** for omit / `"form"` and for built-ins. Startups that set `"json"` on a built-in, or an unknown token, now fail at `ValidateParams`.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_captcha-siteverify`: custom provider may POST siteverify as `application/json` `{"secret","response"}` when the knob is `json`; form/omit stay `PostForm`. Absorb-only `remoteip` if dest later threads the address into `Validate`. Reply classification, gate cookie, and 302 stay as dest.
- `core_plugin_middleware_config-validation`: `ValidateParams` accepts `""` / `form` / `json` (trim, exact lowercase). Reject `json` when provider is not `custom`. Reject unknown values for any provider.

## Impact

- `pkg/configuration/configuration.go` (`CaptchaCustomValidateBody`, `validateCaptcha`)
- `pkg/captcha/captcha.go` (`Client` field, `New`, `Validate` request encoding)
- `pkg/bouncer/bouncer.go` (`Client.New` argument)
- `README.md` (knob + CapJS custom example)
- Captcha / configuration tests (`zzz_`); existing `Client.New` call sites
- Do not change `examples/custom-captcha`, `cache.Client.Set`, dest gate cookie, or siteverify reply classification
