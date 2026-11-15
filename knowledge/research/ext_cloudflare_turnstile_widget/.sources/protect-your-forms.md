---
url: https://developers.cloudflare.com/turnstile/tutorials/login-pages/
title: Protect your forms · Cloudflare Turnstile docs
fetched: 2026-10-16
authority: official
---

Client sample: `<form id="contact-form" action="/submit" method="POST">` with ordinary fields, `<div class="cf-turnstile" data-sitekey="…" data-callback="enableSubmit"></div>`, and a submit button that starts disabled. No hidden input in the markup. Success callback only enables the submit button.

Server sample (ordinary form POST): `const turnstileToken = req.body["cf-turnstile-response"]`. That value is sent to Siteverify as `response`.

When the user submits the form, send both the form data and the Turnstile token to the server.
