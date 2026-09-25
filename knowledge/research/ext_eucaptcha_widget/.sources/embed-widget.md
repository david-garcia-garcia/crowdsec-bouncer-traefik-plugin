---
url: https://docs.eu-captcha.eu/en/getting-started/initial-setup/embed-widget/
title: Embedding the widget - Myra EU CAPTCHA Online Help
fetched: 2026-09-24
authority: official
---

Three steps: script in the head, element at the logo position, server-side token verification.

Script: `https://cdn.eu-captcha.eu/verify.js` with `async defer`.

Widget element: `<div class="eu-captcha" data-sitekey="…"></div>`.

CSP must permit `https://cdn.eu-captcha.eu` and `https://api.eu-captcha.eu`.

This page does not name `data-callback` or the hidden field.
