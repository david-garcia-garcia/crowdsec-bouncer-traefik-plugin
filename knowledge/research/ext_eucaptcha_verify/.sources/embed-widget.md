---
url: https://docs.eu-captcha.eu/en/getting-started/initial-setup/embed-widget/
title: Embedding the widget - Myra EU CAPTCHA Online Help
fetched: 2026-09-24
authority: official
---

Script: `https://cdn.eu-captcha.eu/verify.js` with `async defer`.

Widget element: `<div class="eu-captcha" data-sitekey="…"></div>`.

Server verify sample (abbreviated; conflicts with the verify API page field names):

```
POST https://api.eu-captcha.eu/v1/verify
Content-Type: application/json

{
  "sitekey": "a1b2c3d4-0000-0000-0000-000000000000",
  "secret": "a1b2c3d4••••",
  "token": "TOKEN_FROM_THE_WIDGET"
}
```

This sample uses `token` and omits `client_ip` and `client_user_agent`. It does print `Content-Type: application/json`.

CSP must permit `https://cdn.eu-captcha.eu` and `https://api.eu-captcha.eu`.
