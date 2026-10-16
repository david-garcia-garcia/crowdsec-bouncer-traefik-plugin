---
url: https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/widget-configurations/
title: Widget configurations · Cloudflare Turnstile docs
fetched: 2026-10-16
authority: official
---

Implicit and explicit rendering share the same configuration options (data attributes vs JavaScript render parameters).

Form integration: when enabled, Turnstile automatically creates a hidden input element with the verification token. That input is submitted with the other form data.

- `response-field` / `data-response-field`: whether to create a hidden form field with the token. Default: `true`.
- `response-field-name` / `data-response-field-name`: custom name for that field. Default: `cf-turnstile-response`.

Automatic form integration means the token is included when the form is submitted, requiring no additional JavaScript. Custom field names avoid conflicts. Disabled response fields give full control over token handling.

Complete configuration reference:

- `response-field` / `data-response-field`: a boolean that controls if an input element with the response token is created, defaults to `true`.
- `response-field-name` / `data-response-field-name`: name of the input element, defaults to `cf-turnstile-response`.

Mode-gated settings (these are the ones the page qualifies by mode):

- Widget size applies only to Managed and Non-Interactive. Invisible widgets have no visual footprint regardless of size.
- Appearance modes only affect visible widget types (Managed and Non-Interactive). Invisible widgets are never shown regardless of the appearance setting.
- `refresh-timeout` only applies to widgets of Managed mode.

`response-field` and `response-field-name` are not qualified by widget mode in this table.

Execution: default `render` runs the challenge after render. `execute` defers until `turnstile.execute()`.
