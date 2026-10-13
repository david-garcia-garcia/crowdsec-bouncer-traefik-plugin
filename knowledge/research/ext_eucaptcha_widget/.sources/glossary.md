---
url: https://docs.eu-captcha.eu/en/reference/glossary/
title: Glossary - Myra EU CAPTCHA Online Help
fetched: 2026-09-24
authority: official
---

Token: result of a solved challenge. The widget puts it into the `eu-captcha-response` form field. The server verifies it through the `/verify` endpoint.

verify.js: script of the widget. It creates the challenge in the browser and puts the token into the form.

Widget: component you embed into your form. It runs the challenge and hands over the token.
