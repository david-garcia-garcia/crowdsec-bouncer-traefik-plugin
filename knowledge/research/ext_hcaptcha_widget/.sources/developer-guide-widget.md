---
url: https://docs.hcaptcha.com/
title: Developer Guide | hCaptcha
fetched: 2026-10-16
authority: official
---

Load `https://js.hcaptcha.com/1/api.js` (samples use `async defer`). Add the widget inside the form. After a successful challenge, hCaptcha adds an `h-captcha-response` token to the form submission.

Simple sample: `<form method="POST">` containing ordinary fields, `<div class="h-captcha" data-sitekey="YOUR_SITE_KEY"></div>`, and `<input type="submit">`. No pre-existing hidden input. HTML comment: the hCaptcha flow is triggered and the `h-captcha-response` field is automatically sent as a form field upon clicking Submit.

Empty DOM container (typically a `div`, any element is allowed) must have class `h-captcha` and `data-sitekey`. Typically include the empty `.h-captcha` container inside an HTML form. When a challenge is successfully passed, a hidden token will automatically be added to your form. Retrieve it server-side with POST parameter `h-captcha-response`. On form submit, that token is included with the other POST data after the challenge is passed.

When the challenge succeeded, the hCaptcha script inserted a unique token into your form data. Tokens are retrieved on the server with the `h-captcha-response` POST parameter submitted by the form.

Programmatic JS sample: `api.js?onload=onloadHCaptcha&render=explicit`. `hcaptcha.render('hcaptcha-container', { sitekey, size: 'invisible', callback: onSolve, ... })`. `onSolve(token, key)`: `token` is the `h-captcha-response` value; then `document.getElementById('demo-form').submit()`. Button `preventDefault`s and calls `hcaptcha.execute(widgetId)`. Form contains a name input and `<div id="hcaptcha-container"></div>` — no hidden field in the page markup. The onSolve handler does not copy `token` into an input before `submit()`.
