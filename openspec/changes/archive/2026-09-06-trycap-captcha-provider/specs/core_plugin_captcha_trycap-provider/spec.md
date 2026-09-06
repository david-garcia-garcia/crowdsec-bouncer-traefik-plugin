## Purpose

Lets operators select Cap Standalone (trycap.dev) as a built-in captcha provider so the plugin can render the Cap widget and verify tokens with JSON siteverify.

## ADDED Requirements

### Requirement: trycap is a valid captcha provider
Public `captchaProvider` SHALL accept `trycap` in addition to `hcaptcha`, `recaptcha`, `turnstile`, and `custom`. When `captchaProvider` is `trycap`, `captchaTrycapInstanceUrl` SHALL be a non-empty http or https origin (no site-key path required). `captchaSiteKey` and `captchaSecretKey` SHALL still be required as for other providers. `CaptchaCustom*` SHALL NOT be required for `trycap`.

#### Scenario: trycap with instance URL is valid
- **WHEN** `captchaProvider` is `trycap`, `captchaTrycapInstanceUrl` is `https://cap.example.com`, and site and secret keys are set
- **THEN** plugin initialization accepts the captcha config

#### Scenario: trycap without instance URL is invalid
- **WHEN** `captchaProvider` is `trycap` and `captchaTrycapInstanceUrl` is empty
- **THEN** plugin initialization fails validation

### Requirement: trycap verify uses JSON siteverify
When the provider is `trycap`, a POST with a non-empty `cap-token` form field SHALL be verified by POSTing JSON `{"secret":"<captchaSecretKey>","response":"<token>"}` with `Content-Type: application/json` to `{captchaTrycapInstanceUrl}/{captchaSiteKey}/siteverify`. A JSON body with `success` true SHALL pass. Other providers SHALL keep urlencoded `PostForm` verify. The grace cache key SHALL use Bouncer `remoteIP` from `pkg/ip.GetRemoteIP`; captcha MUST NOT parse `RemoteAddr`.

#### Scenario: JSON success passes
- **WHEN** the client POSTs `cap-token` and the Cap instance returns JSON `{"success":true}` with a JSON content type
- **THEN** the captcha is accepted and the grace cache is set for that remote IP

#### Scenario: Missing cap-token is not a verify call
- **WHEN** the client POSTs without `cap-token`
- **THEN** the plugin does not call siteverify and serves the captcha page

#### Scenario: hcaptcha still PostForms
- **WHEN** `captchaProvider` is `hcaptcha` and the client POSTs the hcaptcha response field
- **THEN** verify is still `application/x-www-form-urlencoded` `secret` and `response`

### Requirement: default captcha page can host the Cap widget
When the provider is `trycap`, the captcha HTML SHALL load the Cap widget script from the built-in jsDelivr `cap-widget` URL as a module and SHALL include `<cap-widget>` with `data-cap-api-endpoint` equal to `{captchaTrycapInstanceUrl}/{captchaSiteKey}/`. When the provider is not `trycap`, the default page SHALL keep the class plus `data-sitekey` widget. Operators MAY still override `captchaFilePath`.

#### Scenario: trycap page exposes Cap API endpoint
- **WHEN** a request is remediating with `trycap` captcha and the default template is used
- **THEN** the HTML includes `data-cap-api-endpoint` pointing at the instance and site key, not a recaptcha-style class widget only

#### Scenario: turnstile page is unchanged
- **WHEN** `captchaProvider` is `turnstile` and the default template is used
- **THEN** the HTML still uses the class plus `data-sitekey` widget
