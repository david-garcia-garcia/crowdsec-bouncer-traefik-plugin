---
url: https://docs.hcaptcha.com/configuration
title: Configuration | hCaptcha
fetched: 2026-10-16
authority: official
---

Script query `recaptchacompat`: `on | off`. Whether or not to insert `window.grecaptcha` compatibility hook. Defaults to `on`.

Container `data-size`: table lists `normal | compact`. Optional. Set the size of the widget. Defaults to `normal`. Compact: smaller footprint via `data-size="compact"`.

`data-callback`: optional. Called when the user submits a successful response. The `h-captcha-response` token is passed to your callback.

`hcaptcha.execute(widgetID)`: triggers the workflow programmatically. Generally used in invisible mode where the target container is a `div` rather than a button.

Fully programmatic pattern is described as "invisible" mode: no checkbox, `.execute()` called by your functions.

The `data-size` table on this page does not list `invisible`.
