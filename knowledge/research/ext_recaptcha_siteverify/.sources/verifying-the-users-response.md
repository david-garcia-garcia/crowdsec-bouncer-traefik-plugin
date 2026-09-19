---
url: https://developers.google.com/recaptcha/docs/verify
title: Verifying the user's response | reCAPTCHA | Google for Developers
fetched: 2026-09-18
authority: official
---

Verification involves sending a POST request to the reCAPTCHA API with the secret key, response token, and optionally, the user's IP address.

URL: `https://www.google.com/recaptcha/api/siteverify`

METHOD: `POST`

| POST Parameter | Description |
| --- | --- |
| secret | Required. The shared key between your site and reCAPTCHA. |
| response | Required. The user response token provided by the reCAPTCHA client-side integration on your site. |
| remoteip | Optional. The user's IP address. |

Each reCAPTCHA user response token is valid for two minutes, and can only be verified once.

Error codes listed on this page: `missing-input-secret`, `invalid-input-secret`, `missing-input-response`, `invalid-input-response`, `bad-request`, `timeout-or-duplicate`. No `missing-remoteip` code is listed.
