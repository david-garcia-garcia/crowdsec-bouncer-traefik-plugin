# Cap Standalone siteverify

How Cap Standalone (trycap.dev / CapJS) verifies a widget token over HTTP.

Fetched: 2026-09-18.

## Request

URL: `POST https://<instance_url>/<site_key>/siteverify`. ([Standalone](https://trycap.dev/guide/standalone/), extract `.sources/standalone.md`; [Quickstart](https://trycap.dev/guide/), extract `.sources/quickstart.md`)

Official examples send JSON only:

| Item | Official value |
| --- | --- |
| Method | `POST` |
| `Content-Type` | `application/json` |
| Body | `{"secret":"<key_secret>","response":"<captcha_token>"}` |

`secret` is the site-key secret from the dashboard, not the instance `ADMIN_KEY`. `response` is the widget token. Official pages do not list `remoteip` or any other request field.

Marketing copy says `/siteverify` is compatible with reCAPTCHA's API. Every official request example (curl, `fetch`, Python `json=`, PHP `json_encode`) is `application/json`, not `application/x-www-form-urlencoded`. This product's dest `Validate` always `PostForm`s urlencoded `secret`+`response`, which does not match those examples.

## Browser token field

When the widget sits inside a form, it injects a hidden input named `cap-token` (override: `data-cap-hidden-field-name`). The token is also `e.detail.token` on the `solve` event. ([Quickstart](https://trycap.dev/guide/); [Widget](https://trycap.dev/guide/widget.html), extract `.sources/widget.md`)

That name is the first hop (browser → plugin). It is already `captchaCustomResponse`. It is not a second provider constant.

## Reply

A valid unused token returns `{ "success": true }`. Tokens are single-use; a second verify of the same token fails. ([Quickstart](https://trycap.dev/guide/))

Official pages do not document request `remoteip`. A later Cap issue about returning verifier IP in the **reply** is not a request-field contract (`comment`, not used here).

## Not this finding

Cap Core (`validateChallenge`) is a different API (JWT challenge, not `/siteverify`). Do not treat it as Standalone siteverify.

This product's wrapper (custom provider + optional JSON body knob) stays in `knowledge/devdocs/`.

## Sources

- Official: [Cap Standalone](https://trycap.dev/guide/standalone/)
- Official: [Cap Quickstart](https://trycap.dev/guide/)
- Official: [Cap Widget](https://trycap.dev/guide/widget.html)
- Extracts: `.sources/`
