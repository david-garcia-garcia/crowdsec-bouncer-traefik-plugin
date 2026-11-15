---
url: https://docs.hcaptcha.com/switch
title: Switch from reCAPTCHA to hCaptcha | hCaptcha
fetched: 2026-10-16
authority: official
---

Client: replace `g-recaptcha` with `h-captcha`. Callbacks and tag attributes do not have to be updated; hCaptcha is API-compatible with reCAPTCHA.

Server: replace the form field `g-recaptcha-response` with `h-captcha-response`.

This page does not say the hCaptcha widget also injects `g-recaptcha-response`.
