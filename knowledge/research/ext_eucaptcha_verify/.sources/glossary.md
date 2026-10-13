---
url: https://docs.eu-captcha.eu/en/reference/glossary/
title: Glossary - Myra EU CAPTCHA Online Help
fetched: 2026-09-24
authority: official
---

Token: result of a solved challenge. The widget puts it into the `eu-captcha-response` form field. The server verifies it through the `/verify` endpoint. Each token is valid one time only.

train mode: condition in which the API skips the verification and sets `success` permanently to `true`. The response then contains `train: true`. See Configuring a sitekey.

verify.js: script of the widget. It creates the challenge in the browser and puts the token into the form.
