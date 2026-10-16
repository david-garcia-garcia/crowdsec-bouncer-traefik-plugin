---
url: https://developers.google.com/recaptcha/docs/verify
title: Verifying the user's response | reCAPTCHA | Google for Developers
fetched: 2026-10-16
authority: official
---

Classic reCAPTCHA verify page (developers.google.com/recaptcha), not Cloud Enterprise assessments.

For web users, get the user’s response token in one of three ways:

- `g-recaptcha-response` POST parameter when the user submits the form on your site
- `grecaptcha.getResponse(opt_widget_id)` after the user completes the reCAPTCHA challenge
- As a string argument to your callback function if `data-callback` is specified in either the `g-recaptcha` tag attribute or the callback parameter in the `grecaptcha.render` method

Each token is valid for two minutes and can only be verified once.

This page does not name a hidden input, textarea, or DOM injection. It names the POST parameter `g-recaptcha-response`.
