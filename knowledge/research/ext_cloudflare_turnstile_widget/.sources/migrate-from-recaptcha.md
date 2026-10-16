---
url: https://developers.cloudflare.com/turnstile/migration/migrating-from-recaptcha/
title: Migrate from reCAPTCHA · Cloudflare Turnstile docs
fetched: 2026-10-16
authority: official
---

Client script for compatibility: `https://challenges.cloudflare.com/turnstile/v0/api.js?compat=recaptcha` with `async defer`.

`?compat=recaptcha` runs Turnstile in compatibility mode, which enables:

- implicit rendering for reCAPTCHA
- `g-recaptcha-response` input name for forms
- register the Turnstile API as `grecaptcha`

This page does not say compatibility mode also injects `cf-turnstile-response`.

Turnstile migration is currently compatible up to reCAPTCHA v2. Turnstile supports `render()` and reCAPTCHA v2 invisible mode with `execute()`.
