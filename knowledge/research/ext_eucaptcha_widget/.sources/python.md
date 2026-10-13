---
url: https://docs.eu-captcha.eu/en/integration/backend/python/
title: Python - Myra EU CAPTCHA Online Help
fetched: 2026-09-24
authority: official
---

Widget: `<div class="eu-captcha" data-sitekey="EUCAPTCHA_SITE_KEY"></div>`.

Script: `https://cdn.eu-captcha.eu/verify.js` with `async defer`.

The script renders the widget, does the challenge, and adds the token to the form.

Full page sample: form with username/password, the `eu-captcha` div, submit input. No hidden `eu-captcha-response` in the markup.

Server reads the field as form alias `eu-captcha-response`.
