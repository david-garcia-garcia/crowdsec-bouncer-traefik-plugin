# Turnstile widget

Official browser widget for Cloudflare Turnstile (`api.js`): script URL, container, hidden form field on ordinary submit, widget modes, and `response-field` contract.

Fetched: 2026-10-16.

## Script URL and container

Load `https://challenges.cloudflare.com/turnstile/v0/api.js` (samples use `async defer`). Implicit rendering scans for elements with class `cf-turnstile` and a `data-sitekey`. Put that container inside the HTML `<form>`. Explicit rendering loads `api.js?render=explicit` and calls `turnstile.render()`. Both methods share the same configuration options. ([Embed the widget](https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/), extract `.sources/embed-the-widget.md`; [Widget configurations](https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/widget-configurations/), extract `.sources/widget-configurations.md`)

The `api.js` file must be fetched from that exact URL. Proxying or caching it will cause Turnstile to fail when updates are released. ([Embed the widget](https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/), extract `.sources/embed-the-widget.md`)

## Hidden field `cf-turnstile-response`

When a Turnstile widget is embedded inside a `<form>` element, an invisible input named `cf-turnstile-response` is automatically created. That field holds the verification token and is submitted with the other form data. Official samples comment the injected node as `<input type="hidden" name="cf-turnstile-response" value="TOKEN_VALUE" />`. The login-form sample is ordinary fields, a `cf-turnstile` div, and a Submit button — no pre-existing hidden input in the markup. ([Embed the widget](https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/), extract `.sources/embed-the-widget.md`)

`response-field` (data attribute `data-response-field`) controls whether that input is created. Default: `true`. `response-field-name` (data attribute `data-response-field-name`) is the input name. Default: `cf-turnstile-response`. Automatic form integration means the token is included when the form is submitted, with no extra JavaScript required. ([Widget configurations](https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/widget-configurations/), extract `.sources/widget-configurations.md`)

The Protect your forms tutorial still reads `req.body["cf-turnstile-response"]` after an ordinary POST, even when `data-callback` only enables the submit button. ([Protect your forms](https://developers.cloudflare.com/turnstile/tutorials/login-pages/), extract `.sources/protect-your-forms.md`)

Migrating from hCaptcha: replace the input name `h-captcha-response` with `cf-turnstile-response`. ([Migrate from hCaptcha](https://developers.cloudflare.com/turnstile/migration/migrating-from-hcaptcha/), extract `.sources/migrate-from-hcaptcha.md`)

## Managed / Non-Interactive / Invisible

Widget modes are Managed, Non-Interactive, and Invisible. Mode is a widget configuration (dashboard / widget record), not a different client field name. ([Turnstile widgets](https://developers.cloudflare.com/turnstile/concepts/widget/), extract `.sources/turnstile-widgets.md`)

| Mode | What the visitor sees | Form field |
| --- | --- | --- |
| Managed (recommended) | Cloudflare chooses non-interactive or a checkbox from visitor risk. Interaction is a checkbox only; no images or text to decipher. | Same `response-field` contract. |
| Non-Interactive | Visible widget with a loading spinner. Visitors are never prompted to interact. | Same `response-field` contract. |
| Invisible | No visible widget and no loading indicators. Challenges run in the background. | Same `response-field` contract. |

([Turnstile widgets](https://developers.cloudflare.com/turnstile/concepts/widget/), extract `.sources/turnstile-widgets.md`; [Widget configurations](https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/widget-configurations/), extract `.sources/widget-configurations.md`)

Official pages that limit a setting by mode say so in the setting itself: widget size and appearance apply only to Managed and Non-Interactive (Invisible has no visual footprint; appearance never shows an Invisible widget); `refresh-timeout` applies only to Managed. `response-field` / `response-field-name` have no such mode caveat. Default remains `true` / `cf-turnstile-response` for every mode. ([Widget configurations](https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/widget-configurations/), extract `.sources/widget-configurations.md`)

Invisible does not document a different token-field name or a skipped hidden input. It documents the absence of a visible widget. ([Turnstile widgets](https://developers.cloudflare.com/turnstile/concepts/widget/), extract `.sources/turnstile-widgets.md`)

## When the field is not created, or not that name

- `data-response-field="false"` (or `response-field: false` on `turnstile.render()`): no input element with the token is created. Token handling is then via callback / `turnstile.getResponse()`. ([Widget configurations](https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/widget-configurations/), extract `.sources/widget-configurations.md`)
- `data-response-field-name="…"`: the input is still created, under a custom name. ([Widget configurations](https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/widget-configurations/), extract `.sources/widget-configurations.md`)
- `api.js?compat=recaptcha`: compatibility mode enables the `g-recaptcha-response` input name for forms (plus implicit reCAPTCHA rendering and a `grecaptcha` API). That is a different documented form field name. ([Migrate from reCAPTCHA](https://developers.cloudflare.com/turnstile/migration/migrating-from-recaptcha/), extract `.sources/migrate-from-recaptcha.md`)

Automatic form integration is documented for a widget inside a `<form>`. The owner pages do not say a widget outside a form still posts `cf-turnstile-response` with some other form. ([Embed the widget](https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/), extract `.sources/embed-the-widget.md`)

Default execution is `render`: the challenge runs after the widget renders. `execution: execute` defers the challenge until `turnstile.execute()`. A submit before a token exists sends whatever is in the field at that moment; the Protect your forms sample disables Submit until the success callback. ([Widget configurations](https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/widget-configurations/), extract `.sources/widget-configurations.md`; [Protect your forms](https://developers.cloudflare.com/turnstile/tutorials/login-pages/), extract `.sources/protect-your-forms.md`)

## Not stated by the owner pages

- That Managed, Non-Interactive, or Invisible skips injecting the token input (mode pages cover visibility and interaction; `response-field` is not mode-gated).
- That a pre-existing hidden `<input>` is required (samples omit it; the widget adds `cf-turnstile-response`).
- That `compat=recaptcha` also keeps injecting `cf-turnstile-response` in addition to `g-recaptcha-response`.

## Sources

- Official: [Embed the widget](https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/)
- Official: [Widget configurations](https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/widget-configurations/)
- Official: [Turnstile widgets](https://developers.cloudflare.com/turnstile/concepts/widget/)
- Official: [Protect your forms](https://developers.cloudflare.com/turnstile/tutorials/login-pages/)
- Official: [Migrate from hCaptcha](https://developers.cloudflare.com/turnstile/migration/migrating-from-hcaptcha/)
- Official: [Migrate from reCAPTCHA](https://developers.cloudflare.com/turnstile/migration/migrating-from-recaptcha/)
- Extracts: `.sources/`
