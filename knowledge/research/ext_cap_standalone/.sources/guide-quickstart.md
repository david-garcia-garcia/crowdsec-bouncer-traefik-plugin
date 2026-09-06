---
url: https://trycap.dev/guide/
title: Quickstart
fetched: 2026-09-06
authority: official
---

Cap = widget (challenge + checkbox) + server (issue + verify). Self-hosted proof-of-work CAPTCHA.

Marketing: Cap's `/siteverify` is compatible with reCAPTCHA's API — change one URL, run side by side, no rewrite.

Recommended server: Cap Standalone (`tiago2/cap:latest`). Dashboard + REST API. Multiple site keys. Compatible with reCAPTCHA siteverify API.

Widget CDN (quickstart): `<script src="https://cdn.jsdelivr.net/npm/cap-widget@<version>"></script>`. Pin version in production; can self-host instead of CDN.

Form integration: widget inside `<form>` auto-injects hidden `cap-token` field; submitted with form. Endpoint: `https://<your-instance>/<site-key>/`.

JavaScript: listen for `solve` event; token at `e.detail.token`.

Verification: POST `https://<your-instance>/<site-key>/siteverify` with `Content-Type: application/json` and body `{ "secret": "<key_secret>", "response": "<captcha_token>" }`. Documented examples: curl, fetch, Python requests (json=), PHP (json_encode + application/json). `<key_secret>` is secret key from dashboard, not ADMIN_KEY. Token from `cap-token` field or `e.detail.token`. Success: `{ "success": true }`.

Tokens are single-use — verify each once; resubmitting the same token should fail.

End-to-end check step 3: send same token again → should fail (confirms single-use).
