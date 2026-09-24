---
url: https://docs.eu-captcha.eu/en/api/verify/
title: Verify a client token - Myra EU CAPTCHA Online Help
fetched: 2026-09-24
authority: official
---

Call only from the server. Secret stays on the server.

Send a POST to the `/verify` endpoint at `https://api.eu-captcha.eu/v1`. No authorization header; authentication is the `secret` field in the body.

This page does not print a `Content-Type` header on the request.

Request body fields (all `string`, all Necessary: yes):

- `sitekey` — public sitekey of the domain the widget is embedded in.
- `secret` — secret that belongs to the sitekey; stays on the server.
- `client_ip` — IPv4 or IPv6 of the visitor, not a proxy or CDN. Examine `X-Forwarded-For` or `X-Client-IP`.
- `client_token` — token from `verify.js`. Comes to the server in the `eu-captcha-response` form field. Empty if the widget did not complete (for example JavaScript off). Always send the field, also with an empty value.
- `client_user_agent` — `User-Agent` header of the visitor. Identifies the type of the client if no token was calculated.

Example body includes all five fields.

HTTP statuses:

- `200` — result of the verification. Examine `success` and `train`.
- `400` — necessary fields missing, or the body is incorrect.
- `429` — request count exceeded. Wait seconds in `Retry-After`, then send again.
- `500` — unexpected error on the server.

HTTP 200 fields:

- `success` (`boolean`) — `true` if the token passed, otherwise `false`. Always also examine `train`, because `success` gets the `true` value when `train` is `true`.
- `train` (`boolean` or `null`) — whether a true verification occurred. `false` and `null` are the usual operation. `true` is a verification that was skipped.
- `error-codes` (`array`) — available only with `success: false`. Names the causes of the failure.

A response with `train: true` means the request was not examined and each transmission counts as successful. This occurs with an unknown sitekey, with a secret that does not agree, and when the protection of the sitekey is off. It also occurs with each other malfunction of the verification.

Error codes (format agrees with reCAPTCHA, hCaptcha, and Turnstile):

- `invalid-input-secret` — secret does not agree with the sitekey.
- `invalid-input-sitekey` — sitekey is unknown.
- `invalid-input-response` — `client_token` was available but not a valid proof (incorrect, not decodable, unsolved, or empty).
- `timeout-or-duplicate` — token used before, or challenge expired. Each token is valid one time.
- `missing-input-secret` — `secret` missing or not a string.
- `missing-input-sitekey` — `sitekey` missing or not a string.
- `missing-input-response` — `client_token` missing or not a string. An empty string counts as available and causes `invalid-input-response`.
- `missing-input-remoteip` — `client_ip` missing or not a string.

Examples:

- Token valid: `{ "success": true, "train": false }`
- Token invalid or used before: `{ "success": false, "train": false }`
- Verification skipped, credentials incorrect: `{ "success": true, "train": true }`
- Error response with `400`, `429`, and `500`: `{ "error": "missing_field", "message": "Required field 'sitekey' is missing." }`

This page does not show an omitted `train` key or a JSON `null` example for `train`.
