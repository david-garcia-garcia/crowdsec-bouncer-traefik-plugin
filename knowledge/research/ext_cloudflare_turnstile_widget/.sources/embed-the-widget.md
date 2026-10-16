---
url: https://developers.cloudflare.com/turnstile/get-started/client-side-rendering/
title: Embed the widget · Cloudflare Turnstile docs
fetched: 2026-10-16
authority: official
---

Implicit rendering scans for class `cf-turnstile`. Script: `https://challenges.cloudflare.com/turnstile/v0/api.js` with `async defer`. Explicit rendering uses `api.js?render=explicit` and `turnstile.render()`.

The `api.js` file must be fetched from that exact URL. Proxying or caching it will cause Turnstile to fail when future updates are released.

Process step 4 (Form integration): the token is made available via callbacks or hidden form fields.

Basic login form sample: `<form action="/login" method="POST">` with username/password, `<div class="cf-turnstile" data-sitekey="…"></div>`, and a submit button. No hidden input in the markup.

After that sample: an invisible input with the name `cf-turnstile-response` is added and will be sent to the server with the other fields.

Automatic form integration: when you embed a Turnstile widget inside a `<form>` element, an invisible input field with the name `cf-turnstile-response` is automatically created. This field contains the verification token and gets submitted with your other form data.

Commented injected node in the automatic-form-integration sample:

```
<input type="hidden" name="cf-turnstile-response" value="TOKEN_VALUE" />
```

Both implicit and explicit rendering support the same configuration options. Token validation is Siteverify. Tokens expire after 300 seconds. Each token can only be validated once.
