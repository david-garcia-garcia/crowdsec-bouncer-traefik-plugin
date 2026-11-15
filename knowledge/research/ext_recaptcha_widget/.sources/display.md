---
url: https://developers.google.com/recaptcha/docs/display
title: reCAPTCHA v2 | Google for Developers
fetched: 2026-10-16
authority: official
---

Page is classic reCAPTCHA v2 checkbox widget (developers.google.com/recaptcha), not Cloud Enterprise.

Script: `https://www.google.com/recaptcha/api.js` with `async defer`. Explicit render: `api.js?onload=onloadCallback&render=explicit`. Default `render=onload` renders the first `g-recaptcha` tag.

Automatic render: a DIV with class `g-recaptcha` and `data-sitekey`. Official form:

```
<form action="?" method="POST">
  <div class="g-recaptcha" data-sitekey="your_site_key"></div>
  <br/>
  <input type="submit" value="Submit">
</form>
```

No author-written field named `g-recaptcha-response`.

`data-callback` / `callback`: optional. Executed when the user submits a successful response. The `g-recaptcha-response` token is passed to the callback.

`grecaptcha.getResponse(opt_widget_id)` gets the response for the widget.

Explicit-render sample 3 HTML comment: “POSTs back to the page's URL upon submit with a g-recaptcha-response POST parameter.” That form is `action="?" method="POST"` with an empty `#example3` container and a submit button only.

See Verifying the user's response to check if the user successfully solved the CAPTCHA.
