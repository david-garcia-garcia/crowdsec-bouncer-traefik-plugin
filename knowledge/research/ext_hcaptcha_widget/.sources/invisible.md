---
url: https://docs.hcaptcha.com/invisible
title: Invisible Captcha | hCaptcha
fetched: 2026-10-16
authority: official
---

Invisible: no checkbox. Client/server interactions in the background; a challenge is shown only if the user meets challenge criteria. Available to all users. Set as described on this page (container `data-size="invisible"`).

Passive: checkbox is displayed; no visible challenge. Set via the sitekey difficulty. Requires consuming the hCaptcha risk score. Enterprise only.

Invisible + Passive: no checkbox and no visible challenge. Enterprise. Lower protection than active challenge modes.

99.9% Passive: Pro and Enterprise. Selectively challenges users. Not a separate form-field name.

Bind to a button or input: assign class `h-captcha` plus `data-sitekey` (and other `data-*`). The response token is sent to the callback on successful completion. If attached to a submit button, you must specify `data-callback` to handle form submission. In most cases use the callback to manually submit the form. Sample: `function onSubmit(token) { document.getElementById('my-form').submit(); }`.

Programmatic: same as explicit render; if `data-size="invisible"` is present, the widget is rendered in the background and only presented when a challenge is required. `hcaptcha.execute(widgetID)` invokes the workflow from JS.

Execute sample: form with a text field, a `div.h-captcha` with `data-sitekey`, `data-callback="onSubmit"`, `data-size="invisible"`, and a separate submit button. Click handler `preventDefault`s, then `hcaptcha.execute()`. `onSubmit(token)` alerts; it does not submit the form in that sample.

This page does not restate that a hidden `h-captcha-response` field is automatically added to the form.
