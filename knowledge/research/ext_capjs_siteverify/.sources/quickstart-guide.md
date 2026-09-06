---
url: https://trycap.dev/guide/
title: Cap Quickstart
fetched: 2026-09-06
authority: official
---

Cap Standalone exposes REST API compatible with reCAPTCHA siteverify API.

Verify token: POST to instance `/siteverify` endpoint.

Content-Type: application/json.

Request body JSON keys: secret (key_secret from dashboard), response (captcha_token from widget).

Widget in form auto-injects hidden cap-token field. JS: solve event e.detail.token.

Success response: { "success": true }.

Tokens single-use; resubmit same token fails.

Endpoint pattern: https://<your-instance>/<site-key>/siteverify
