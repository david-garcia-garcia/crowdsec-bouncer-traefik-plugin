---
url: https://developers.google.com/recaptcha/docs/invisible
title: Invisible reCAPTCHA | Google for Developers
fetched: 2026-10-16
authority: official
---

Page is classic invisible reCAPTCHA v2 (developers.google.com/recaptcha), not Cloud Enterprise.

Invoke by: automatically binding the challenge to a button, programmatically binding to a button, or programmatically invoking it.

Script: `https://www.google.com/recaptcha/api.js` with `async defer`.

Automatic bind: class `g-recaptcha` on the HTML button, `data-sitekey`, and `data-callback`. Official sample `onSubmit(token)` calls `document.getElementById("demo-form").submit()` and does not assign `token` to a form field. Form markup is the button only.

Programmatic invoke: a `div` with class `g-recaptcha`, `data-sitekey`, `data-callback`, and `data-size="invisible"`, then `grecaptcha.execute()`. After client-side validation sample: `onSubmit(token)` only alerts; it does not POST the form. Form markup includes an ordinary named field, the invisible div, and a separate submit button.

`data-callback` / `callback`: optional in the attribute table. Executed when the user submits a successful response. The `g-recaptcha-response` token is passed to the callback.

`grecaptcha.getResponse(opt_widget_id)` gets the response for the widget.

See Verifying the user's response to check if the user successfully solved the CAPTCHA.
