---
url: https://developers.cloudflare.com/turnstile/migration/migrating-from-hcaptcha/
title: Migrate from hCaptcha · Cloudflare Turnstile docs
fetched: 2026-10-16
authority: official
---

Client script: `https://challenges.cloudflare.com/turnstile/v0/api.js` with `async defer`. Replace `hcaptcha.render()` with `turnstile.render()`.

Server: replace Siteverify URL with `https://challenges.cloudflare.com/turnstile/v0/siteverify`.

Replace the `h-captcha-response` input name with `cf-turnstile-response`.
