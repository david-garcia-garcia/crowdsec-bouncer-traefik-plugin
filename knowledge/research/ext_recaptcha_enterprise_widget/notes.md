# Enterprise widget

Official browser API for Google Cloud reCAPTCHA Enterprise checkbox keys and score keys.

Fetched: 2026-09-24.

## Script URL

Checkbox automatic render loads `https://www.google.com/recaptcha/enterprise.js` (no `render=` site key). Explicit checkbox render uses `enterprise.js?onload=...&render=explicit`. ([Install checkbox keys](https://cloud.google.com/recaptcha/docs/instrument-web-pages-with-checkbox), extract `.sources/instrument-web-pages-with-checkbox.md`)

Score keys load `https://www.google.com/recaptcha/enterprise.js?render=KEY_ID`. `render` is required for score keys. If that `render=siteKey` form is used with a checkbox key, the script will not load. ([Install score-based keys](https://cloud.google.com/recaptcha/docs/instrument-web-pages), extract `.sources/instrument-web-pages.md`; [JavaScript API reference](https://cloud.google.com/recaptcha/docs/api-ref-checkbox-keys), extract `.sources/api-ref-checkbox-keys.md`)

Default `render=onload` renders the first `g-recaptcha` tag (checkbox only). ([JavaScript API reference](https://cloud.google.com/recaptcha/docs/api-ref-checkbox-keys), extract `.sources/api-ref-checkbox-keys.md`)

## Checkbox class, field, callback, action

Checkbox still uses class `g-recaptcha` and `data-sitekey`. Optional `data-action` sets the action name. ([Install checkbox keys](https://cloud.google.com/recaptcha/docs/instrument-web-pages-with-checkbox), extract `.sources/instrument-web-pages-with-checkbox.md`; [JavaScript API reference](https://cloud.google.com/recaptcha/docs/api-ref-checkbox-keys), extract `.sources/api-ref-checkbox-keys.md`)

Token field: `g-recaptcha-response` POST parameter on form submit. The same token is the argument to `data-callback`. ([Create assessments for websites](https://cloud.google.com/recaptcha/docs/create-assessment-website), extract `.sources/create-assessment-website.md`; [JavaScript API reference](https://cloud.google.com/recaptcha/docs/api-ref-checkbox-keys), extract `.sources/api-ref-checkbox-keys.md`)

`data-callback` / `callback`: optional. Runs on a successful response and receives the `g-recaptcha-response` token. ([JavaScript API reference](https://cloud.google.com/recaptcha/docs/api-ref-checkbox-keys), extract `.sources/api-ref-checkbox-keys.md`)

`grecaptcha.enterprise.reset` clears a checkbox widget so it can be solved again. ([JavaScript API reference](https://cloud.google.com/recaptcha/docs/api-ref-checkbox-keys), extract `.sources/api-ref-checkbox-keys.md`)

## Score boot

1. Load `enterprise.js?render={siteKey}`.
2. Call `grecaptcha.enterprise.ready(...)`.
3. Inside that callback, `await grecaptcha.enterprise.execute(siteKey, {action})`.

Official sample uses `{action: 'LOGIN'}`. Call `execute` on each interaction you want to protect. Send the token to the backend within two minutes. ([Install score-based keys](https://cloud.google.com/recaptcha/docs/instrument-web-pages), extract `.sources/instrument-web-pages.md`; method shape [JavaScript API reference](https://cloud.google.com/recaptcha/docs/api-ref-checkbox-keys), extract `.sources/api-ref-checkbox-keys.md`)

Conflict: a score-key HTML **button** can still use `class="g-recaptcha"`, `data-callback`, `data-action`, and POST `g-recaptcha-response`. That is the button integration on the score page, not the checkbox widget. The programmatic score path is `ready` then `execute`. ([Install score-based keys](https://cloud.google.com/recaptcha/docs/instrument-web-pages), extract `.sources/instrument-web-pages.md`)

## Token reuse / retry `execute`

Each token can be assessed only once. For a later action, or if the token expires before assessment, call `execute()` again to mint a new token. Re-assessing the same token is `DUPE` on the Assessment (see `ext_recaptcha_enterprise_assessments/`). ([Create assessments for websites](https://cloud.google.com/recaptcha/docs/create-assessment-website), extract `.sources/create-assessment-website.md`)

Official pages do not say to omit `enterprise.js` after a refused score. They say to call `execute` on each protected interaction. A new `execute()` returns a new token; it does not reuse the assessed one. Whether a product omits the boot script after reject is not a Google requirement. ([Install score-based keys](https://cloud.google.com/recaptcha/docs/instrument-web-pages), extract `.sources/instrument-web-pages.md`; [Create assessments for websites](https://cloud.google.com/recaptcha/docs/create-assessment-website), extract `.sources/create-assessment-website.md`)

## Sources

- Official: [Install score-based keys on websites](https://cloud.google.com/recaptcha/docs/instrument-web-pages)
- Official: [Install checkbox keys (checkbox challenge) on websites](https://cloud.google.com/recaptcha/docs/instrument-web-pages-with-checkbox)
- Official: [JavaScript API reference for reCAPTCHA](https://cloud.google.com/recaptcha/docs/api-ref-checkbox-keys)
- Official: [Create assessments for websites](https://cloud.google.com/recaptcha/docs/create-assessment-website)
- Extracts: `.sources/`
