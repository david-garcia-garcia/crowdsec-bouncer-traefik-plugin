# Widget

Official browser widget for Myra EU CAPTCHA (`verify.js`): script URL, container class, `data-*` attributes, hidden field, and callback.

Fetched: 2026-09-24.

## Script URL

Load `https://cdn.eu-captcha.eu/verify.js` (samples use `async defer`), usually in the head. ([Embedding the widget](https://docs.eu-captcha.eu/en/getting-started/initial-setup/embed-widget/), extract `.sources/embed-widget.md`; [HTML and JavaScript](https://docs.eu-captcha.eu/en/integration/frontend/html-javascript/), extract `.sources/html-javascript.md`; [How EU CAPTCHA works](https://docs.eu-captcha.eu/en/introduction/how-it-works/), extract `.sources/how-it-works.md`)

CSP must permit `https://cdn.eu-captcha.eu` and `https://api.eu-captcha.eu`. ([Embedding the widget](https://docs.eu-captcha.eu/en/getting-started/initial-setup/embed-widget/), extract `.sources/embed-widget.md`)

## Container class and `data-*`

Canonical element:

```
<div class="eu-captcha" data-sitekey="…"></div>
```

Class `eu-captcha`. `data-sitekey` is necessary. ([HTML and JavaScript](https://docs.eu-captcha.eu/en/integration/frontend/html-javascript/), extract `.sources/html-javascript.md`; [Embedding the widget](https://docs.eu-captcha.eu/en/getting-started/initial-setup/embed-widget/), extract `.sources/embed-widget.md`)

`verify.js` reads these attributes:

| Attribute | Default | Effect |
| --- | --- | --- |
| `data-sitekey` | — | Public sitekey. Necessary. |
| `data-theme` | `"light"` | `"light"` or `"dark"`. |
| `data-width` | `330` | Width in pixels. |
| `data-height` | `100` | Height in pixels. |
| `data-widgetid` | automatic | Own identifier of the widget. |
| `data-autostart` | `"true"` | `"false"` delays the start of the challenge. |
| `data-callback` | — | Name of a global function called after the challenge passed. |
| `data-expired-callback` | — | Name of a global function called when the token expires. |
| `data-error-callback` | — | Name of a global function called when an error occurs. |

([HTML and JavaScript](https://docs.eu-captcha.eu/en/integration/frontend/html-javascript/), extract `.sources/html-javascript.md`)

The owner does not mention the identifier `captchaCallback`. The attribute name is `data-callback`.

## Hidden field `eu-captcha-response`

`verify.js` writes the token into a hidden input named `eu-captcha-response`. ([How EU CAPTCHA works](https://docs.eu-captcha.eu/en/introduction/how-it-works/), extract `.sources/how-it-works.md`; [Glossary](https://docs.eu-captcha.eu/en/reference/glossary/), extract `.sources/glossary.md`)

During transmission, the widget adds that hidden field with the token. ([HTML and JavaScript](https://docs.eu-captcha.eu/en/integration/frontend/html-javascript/), extract `.sources/html-javascript.md`)

The widget makes the hidden `eu-captcha-response` field itself, which goes with the form. The HTML+Django sample is a `<form>` that contains only ordinary fields, the `eu-captcha` div, and a submit button — no pre-existing hidden input. The script starts the challenge automatically and puts the field in the form. ([HTML and Django](https://docs.eu-captcha.eu/en/integration/examples/html-django/), extract `.sources/html-django.md`)

The Python sample is the same shape: form + `div.eu-captcha` + submit, no hidden input in the markup. The script renders the widget, does the challenge, and adds the token to the form. ([Python](https://docs.eu-captcha.eu/en/integration/backend/python/), extract `.sources/python.md`)

A page that only has the class + `data-sitekey` (the canonical sample) is what those owners document. `data-callback` is optional (default “—”). The owners do not say a pre-existing hidden input is required. They do not say adding `data-callback` changes whether the widget injects `eu-captcha-response`.

## Callback contract

HTML `data-callback`: name of a global function that is called after the challenge passed. That table does not name arguments. It does not say the function receives the token. It does not say the function submits the form. ([HTML and JavaScript](https://docs.eu-captcha.eu/en/integration/frontend/html-javascript/), extract `.sources/html-javascript.md`)

The npm / React `onComplete` option is `(token: string) => void` — called with the token when the challenge passed. That is the package option, not the HTML `data-callback` attribute. ([HTML and JavaScript](https://docs.eu-captcha.eu/en/integration/frontend/html-javascript/), extract `.sources/html-javascript.md`; [React](https://docs.eu-captcha.eu/en/integration/frontend/react/), extract `.sources/react.md`)

The HTML+Django note says that in a single-page application you accept the token with a callback and send it as JSON instead. ([HTML and Django](https://docs.eu-captcha.eu/en/integration/examples/html-django/), extract `.sources/html-django.md`)

Auto-submit: not stated. Samples keep a submit button. The visitor sends the form; the widget solves the challenge in the background. ([Testing the integration](https://docs.eu-captcha.eu/en/getting-started/initial-setup/test-integration/), extract `.sources/test-integration.md`; [HTML and JavaScript](https://docs.eu-captcha.eu/en/integration/frontend/html-javascript/), extract `.sources/html-javascript.md`) `data-autostart` default `"true"` starts the challenge, not a form POST.

Default mode Solved Immediate: verification starts as soon as the page is loaded, so it can already be complete when users submit. ([How EU CAPTCHA works](https://docs.eu-captcha.eu/en/introduction/how-it-works/), extract `.sources/how-it-works.md`)

Conflict: HTML/Django listen for window message type `euCaptchaCompleted`. ([HTML and JavaScript](https://docs.eu-captcha.eu/en/integration/frontend/html-javascript/), extract `.sources/html-javascript.md`; [HTML and Django](https://docs.eu-captcha.eu/en/integration/examples/html-django/), extract `.sources/html-django.md`) The React page listens for `euCaptchaDone`. ([React](https://docs.eu-captcha.eu/en/integration/frontend/react/), extract `.sources/react.md`) For the vanilla `verify.js` widget, follow HTML and JavaScript / HTML and Django (`euCaptchaCompleted`).

## Not stated by the owner pages

- Arguments of the HTML `data-callback` global function (whether it receives the token).
- That `data-callback` auto-submits the form (samples use a submit button).
- The function name `captchaCallback`.
- That a pre-existing hidden `<input>` is required (samples omit it; the widget adds `eu-captcha-response`).

## Sources

- Official: [HTML and JavaScript](https://docs.eu-captcha.eu/en/integration/frontend/html-javascript/)
- Official: [Embedding the widget](https://docs.eu-captcha.eu/en/getting-started/initial-setup/embed-widget/)
- Official: [How EU CAPTCHA works](https://docs.eu-captcha.eu/en/introduction/how-it-works/)
- Official: [HTML and Django](https://docs.eu-captcha.eu/en/integration/examples/html-django/)
- Official: [Python](https://docs.eu-captcha.eu/en/integration/backend/python/)
- Official: [Glossary](https://docs.eu-captcha.eu/en/reference/glossary/)
- Official: [React](https://docs.eu-captcha.eu/en/integration/frontend/react/)
- Official: [Testing the integration](https://docs.eu-captcha.eu/en/getting-started/initial-setup/test-integration/)
- Extracts: `.sources/`
