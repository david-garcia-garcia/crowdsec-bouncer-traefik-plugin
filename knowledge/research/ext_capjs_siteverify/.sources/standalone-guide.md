---
url: https://trycap.dev/guide/standalone/
title: Cap Standalone
fetched: 2026-09-06
authority: official
---

Cap Standalone siteverify API compatible with reCAPTCHA.

Server verify: POST https://<instance_url>/<site_key>/siteverify

Content-Type: application/json

Body: { "secret": "<key_secret>", "response": "<captcha_token>" }

key_secret = site secret from dashboard (not ADMIN_KEY).

captcha_token = challenge token from widget.

Success: { "success": true }
