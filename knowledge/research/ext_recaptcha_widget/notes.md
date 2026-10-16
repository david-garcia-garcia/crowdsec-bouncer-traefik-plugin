# Widget

Official browser widget for Google reCAPTCHA v2 classic (checkbox and invisible). Not Enterprise (`ext_recaptcha_enterprise_widget/`). Not v3.

Fetched: 2026-10-16.

## Script URL

Checkbox and invisible both load `https://www.google.com/recaptcha/api.js` (`async defer`). Explicit render adds `?onload=…&render=explicit`. ([reCAPTCHA v2](https://developers.google.com/recaptcha/docs/display), extract `.sources/display.md`; [Invisible reCAPTCHA](https://developers.google.com/recaptcha/docs/invisible), extract `.sources/invisible.md`)

## Checkbox ("I'm not a robot")

Automatic render: a `div` with class `g-recaptcha` and `data-sitekey`. The official form sample is `method="POST"` with that div and a submit button — no author-written `g-recaptcha-response` control. ([reCAPTCHA v2](https://developers.google.com/recaptcha/docs/display), extract `.sources/display.md`; type name [Choosing the type of reCAPTCHA](https://developers.google.com/recaptcha/docs/versions), extract `.sources/versions.md`)

Explicit render: `grecaptcha.render` into a container. The third official sample comments that native submit **POSTs back … with a `g-recaptcha-response` POST parameter**. That form’s markup is an empty render target plus a submit button. ([reCAPTCHA v2](https://developers.google.com/recaptcha/docs/display), extract `.sources/display.md`)

`data-callback` is optional. On success the `g-recaptcha-response` token is passed to that callback. `grecaptcha.getResponse` returns the same token. ([reCAPTCHA v2](https://developers.google.com/recaptcha/docs/display), extract `.sources/display.md`)

## Invisible

Three invocation styles: bind the challenge to a button automatically, bind it programmatically, or call `grecaptcha.execute` on a `div` with `data-size="invisible"`. The versions page says this integration **requires a JavaScript callback** when verification is complete. ([Invisible reCAPTCHA](https://developers.google.com/recaptcha/docs/invisible), extract `.sources/invisible.md`; [Choosing the type of reCAPTCHA](https://developers.google.com/recaptcha/docs/versions), extract `.sources/versions.md`)

Automatic button bind: the submit control itself has class `g-recaptcha`, `data-sitekey`, and `data-callback`. The official `onSubmit(token)` sample calls `form.submit()` and does not copy `token` into a field. Conflict: that intro lists `data-callback` as a necessary attribute; the attribute table marks it optional; the versions page says invisible integration requires a JavaScript callback. For auto-bind, follow the intro and versions (callback required). ([Invisible reCAPTCHA](https://developers.google.com/recaptcha/docs/invisible), extract `.sources/invisible.md`; [Choosing the type of reCAPTCHA](https://developers.google.com/recaptcha/docs/versions), extract `.sources/versions.md`)

Programmatic `data-size="invisible"` sample: `grecaptcha.execute()` after client-side validation; `onSubmit(token)` only alerts. It does not POST the form. ([Invisible reCAPTCHA](https://developers.google.com/recaptcha/docs/invisible), extract `.sources/invisible.md`)

`data-callback` receives the `g-recaptcha-response` token. `grecaptcha.getResponse` is also documented. ([Invisible reCAPTCHA](https://developers.google.com/recaptcha/docs/invisible), extract `.sources/invisible.md`)

## `g-recaptcha-response` on form submit

For web users the token is available in three ways: the `g-recaptcha-response` **POST parameter when the user submits the form**, `grecaptcha.getResponse`, or the `data-callback` / `grecaptcha.render` `callback` string argument. Both widget pages send the reader to that owner. ([Verifying the user's response](https://developers.google.com/recaptcha/docs/verify), extract `.sources/verifying-the-users-response.md`; [reCAPTCHA v2](https://developers.google.com/recaptcha/docs/display), extract `.sources/display.md`; [Invisible reCAPTCHA](https://developers.google.com/recaptcha/docs/invisible), extract `.sources/invisible.md`)

Checkbox: native submit of the form that contains the widget posts `g-recaptcha-response`. Author HTML does not include that named field. ([reCAPTCHA v2](https://developers.google.com/recaptcha/docs/display), extract `.sources/display.md`; [Verifying the user's response](https://developers.google.com/recaptcha/docs/verify), extract `.sources/verifying-the-users-response.md`)

Invisible: the same verify page lists the POST parameter for web users. The auto-bind sample submits the containing form without writing the callback token into markup. The programmatic sample does not submit a form; it delivers the token through the callback. ([Invisible reCAPTCHA](https://developers.google.com/recaptcha/docs/invisible), extract `.sources/invisible.md`; [Verifying the user's response](https://developers.google.com/recaptcha/docs/verify), extract `.sources/verifying-the-users-response.md`)

Official pages do not say the widget injects a hidden `<input>` or `<textarea>`, and they do not show the widget’s inner HTML. Native form POST of a named parameter from markup that has no such control means a named control is present in that form at submit time (`authority: inference`, from the verify POST-parameter claim plus the checkbox and invisible auto-bind samples). They do not name the control type.

## Not stated by the owner pages

- Element type of `g-recaptcha-response` (`<input type="hidden">` vs `<textarea>` vs other).
- The verbs “inject” / “hidden field”.
- That a pre-existing named control is required (samples omit it).
- That the programmatic invisible path POSTs `g-recaptcha-response` (that sample does not submit).

## Sources

- Official: [reCAPTCHA v2](https://developers.google.com/recaptcha/docs/display)
- Official: [Invisible reCAPTCHA](https://developers.google.com/recaptcha/docs/invisible)
- Official: [Verifying the user's response](https://developers.google.com/recaptcha/docs/verify)
- Official: [Choosing the type of reCAPTCHA](https://developers.google.com/recaptcha/docs/versions)
- Extracts: `.sources/`
