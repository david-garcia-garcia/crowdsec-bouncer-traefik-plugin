---
url: https://cloud.google.com/recaptcha/docs/api-ref-checkbox-keys
title: JavaScript API reference for reCAPTCHA | Google Cloud Fraud Defense
fetched: 2026-09-24
authority: official
---

`grecaptcha.enterprise.ready(callback)`: run `callback` when the library has loaded.

`grecaptcha.enterprise.execute`:

- Checkbox: `execute(widget_id?: number): Promise<string>`
- Score: `execute(sitekey: string, action: Object): Promise<string>` with `{ "action": "action_name" }`

`grecaptcha.enterprise.reset(widget_id?)` resets the widget (checkbox).

`grecaptcha.enterprise.getResponse(widget_id?)` returns the token string, or empty if none yet.

`enterprise.js` query `render`:

- `onload` (default): render the first `g-recaptcha` tag. Checkbox only.
- `explicit`: do not auto-render; call `render()`. Checkbox only.
- `siteKey`: required for score-based keys. If used with checkbox keys, the script will not load.

`g-recaptcha` attributes / `render()` parameters:

- `data-sitekey` / `sitekey`
- `data-action` / `action` (optional string)
- `data-callback` / `callback`: on successful response, the `g-recaptcha-response` token is passed to the callback.

Last updated 2026-09-18 UTC on fetch.
