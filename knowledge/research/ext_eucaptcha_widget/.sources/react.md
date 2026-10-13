---
url: https://docs.eu-captcha.eu/en/integration/frontend/react/
title: React - Myra EU CAPTCHA Online Help
fetched: 2026-09-24
authority: official
---

Package `@myrasec/eu-captcha`. Property `onComplete`: `(token: string) => void` — called with the token as soon as the challenge passed.

`onExpired` and `onError` take no token argument.

Without React, add `<div class="eu-captcha" data-sitekey="EUCAPTCHA_SITE_KEY"></div>`. Permitted attributes are given in HTML and JavaScript.

Window message sample on this page uses type `euCaptchaDone` (conflicts with HTML and JavaScript / HTML and Django `euCaptchaCompleted`).
