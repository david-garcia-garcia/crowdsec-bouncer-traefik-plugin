---
url: https://docs.eu-captcha.eu/en/integration/examples/html-django/
title: HTML and Django - Myra EU CAPTCHA Online Help
fetched: 2026-09-24
authority: official
---

The form sends a usual POST. The widget makes the hidden `eu-captcha-response` field itself, which goes with the form.

In a single-page application, you accept the token with a callback and send it as JSON instead.

Sample markup: script `https://cdn.eu-captcha.eu/verify.js`, form with email/message fields, `<div class="eu-captcha" data-sitekey="EUCAPTCHA_SITE_KEY"></div>`, submit button. No pre-existing hidden input.

The script makes the hidden iframe, starts the challenge automatically, and puts the hidden `eu-captcha-response` field in the form.

Optional: disable the submit button until window message type `euCaptchaCompleted` from origin `https://cdn.eu-captcha.eu`.
