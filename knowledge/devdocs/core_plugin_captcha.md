# Captcha Client

## Language

**Captcha Client**:
`pkg/captcha.Client` on Bouncer. Renders the operator captcha template or POSTs the solved token to the provider verify URL. Not LAPI, not AppSec JSON `action: captcha`.
_Avoid_: AppSec challenge, LAPI Client, CrowdsecConnection

**infoProvider**:
JS URL, widget class or element, form field name, and verify URL for one `captchaProvider` value. Built-ins come from the package map; `custom` copies `CaptchaCustom*`.
_Avoid_: site key, secret key, grace cache

## Overview

Put captcha and templates on Bouncer. `bouncer.New` calls `captcha.Client.New`. `ServeHTTP` uses `Check(remoteIP)` then `captcha.ServeHTTP` when the remediation is captcha and the method is not HEAD.

## How to use

- Add a built-in by a `CaptchaProvider` constant, an `infoProviders` row, and `validateCaptcha` allowlist. Do not overload `custom` for a provider whose verify encoding is not urlencoded `PostForm`.
- Self-hosted providers whose verify URL includes the site key: take an instance origin on Config, join `{instance}/{siteKey}/` and `{instance}/{siteKey}/siteverify` in `New`. Do not make the operator paste the joined siteverify URL into `CaptchaCustomValidateURL`.
- Template execute map today: `SiteKey`, `FrontendJS`, `FrontendKey`. A provider that is not class+`data-sitekey` must pass extra keys and branch in `captcha.html`. Keep one default file; `captchaFilePath` stays the operator override.
- `Validate` reads `r.FormValue(infoProvider.response)`. Urlencoded providers use `PostForm` `secret`+`response`. JSON providers POST `application/json` `{"secret","response"}` and still decode `success`.
- Grace cache key is `remoteIP+"_captcha"`. `remoteIP` is Bouncer `clientRequest.remoteIP` from `pkg/ip.GetRemoteIP`. Do not parse `RemoteAddr` in this package.

## Pattern snippet

```go
err := routeHandler.captchaClient.New(
	log, lapiClient.Cache(), httpClient,
	config.CaptchaProvider,
	config.CaptchaCustomJsURL, config.CaptchaCustomKey,
	config.CaptchaCustomResponse, config.CaptchaCustomValidateURL,
	config.CaptchaSiteKey, config.CaptchaSecretKey,
	config.RemediationHeadersCustomName,
	config.CaptchaFilePath, config.CaptchaGracePeriodSeconds,
)
```

## Key files

- `pkg/captcha/captcha.go`
- `pkg/configuration/configuration.go` (`validateCaptcha`, `GetTemplate`)
- `pkg/bouncer/bouncer.go`
- `captcha.html`

## Gotchas

- Default `captcha.html` assumes a class-based widget and `data-callback="captchaCallback"`. Cap Standalone uses `<cap-widget>` plus `type="module"` script and hidden `cap-token`.
- `custom` always `PostForm`s. A JSON siteverify provider cannot be configured as `custom` without an adapter.
- Captcha is not on the LAPI reclaim key (`core_plugin_middleware`).
