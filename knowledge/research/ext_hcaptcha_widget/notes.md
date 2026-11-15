# Widget

Official browser widget for hCaptcha (`api.js`): script URL, container, documented modes, and the form token field on submit.

Fetched: 2026-10-16.

## Script URL and container

Load `https://js.hcaptcha.com/1/api.js` (samples use `async defer`). Add an empty DOM container with class `h-captcha` and `data-sitekey` set to the public sitekey. Put that container inside the HTML form. ([Developer Guide](https://docs.hcaptcha.com/), extract `.sources/developer-guide-widget.md`)

## Hidden field `h-captcha-response`

After a successful challenge, hCaptcha adds an `h-captcha-response` token to the form submission. When the challenge is passed, a hidden token is automatically added to the form. Retrieve it server-side as POST parameter `h-captcha-response`. The script inserts that unique token into the form data. ([Developer Guide](https://docs.hcaptcha.com/), extract `.sources/developer-guide-widget.md`)

The simple sample is a `<form>` with ordinary fields, an empty `.h-captcha` div, and a submit control — no pre-existing hidden input. The HTML comment says the `h-captcha-response` field is automatically sent as a form field upon clicking Submit. ([Developer Guide](https://docs.hcaptcha.com/), extract `.sources/developer-guide-widget.md`)

The official Node.js integration reads `h-captcha-response` from the submitted form. The official React component inside a `<form method="POST">` sends `h-captcha-response` with the other fields; that JSX has no extra hidden input. ([Node.js](https://docs.hcaptcha.com/integrations/node), extract `.sources/integrations-node.md`; [React](https://docs.hcaptcha.com/integrations/react), extract `.sources/integrations-react.md`)

Switching from reCAPTCHA: replace the form field name `g-recaptcha-response` with `h-captcha-response`. Official pages do not say the hCaptcha widget also injects `g-recaptcha-response`. The `recaptchacompat` script query (default `on`) inserts a `window.grecaptcha` compatibility hook, not a second documented form field. ([Switch from reCAPTCHA](https://docs.hcaptcha.com/switch), extract `.sources/switch.md`; [Configuration](https://docs.hcaptcha.com/configuration), extract `.sources/configuration.md`)

Official pages call it a hidden token / form field / POST parameter. They do not name the DOM node type (`<input type="hidden">` vs `<textarea>`).

## Checkbox / visible widget (`normal`, `compact`)

`data-size` on the container: `normal` (default) or `compact`. Compact is a smaller footprint of the same widget. Ordinary form Submit with the `.h-captcha` container inside the form is the documented path. ([Configuration](https://docs.hcaptcha.com/configuration), extract `.sources/configuration.md`; [Developer Guide](https://docs.hcaptcha.com/), extract `.sources/developer-guide-widget.md`)

`data-callback` is optional. On a successful response it receives the `h-captcha-response` token. The simple checkbox sample does not set it. ([Configuration](https://docs.hcaptcha.com/configuration), extract `.sources/configuration.md`)

## Invisible (`data-size="invisible"`)

"Invisible" means no checkbox. Available to all users. Set `data-size="invisible"` on the container, or `size: 'invisible'` on `hcaptcha.render()`. The widget is rendered in the background and only shown when a challenge is required. ([Invisible Captcha](https://docs.hcaptcha.com/invisible), extract `.sources/invisible.md`; [Developer Guide](https://docs.hcaptcha.com/), extract `.sources/developer-guide-widget.md`)

Conflict: the Configuration attribute table lists `data-size` as `normal | compact` only. The Invisible page and the Developer Guide programmatic sample own `invisible`. Follow those two for this mode. ([Configuration](https://docs.hcaptcha.com/configuration), extract `.sources/configuration.md`)

Token name is still `h-captcha-response`. `data-callback` receives that token. The Developer Guide execute sample comments that `token` is the `h-captcha-response` value, then calls `form.submit()`. That sample does not copy the token into a field in page script. ([Developer Guide](https://docs.hcaptcha.com/), extract `.sources/developer-guide-widget.md`; [Configuration](https://docs.hcaptcha.com/configuration), extract `.sources/configuration.md`)

Two documented trigger paths — neither is unintercepted ordinary Submit:

| Path | Container | How submit works |
| --- | --- | --- |
| Bind to a button or input | `class="h-captcha"` on the `button` or `input`, plus `data-sitekey` | You must set `data-callback` to handle form submission. In most cases submit the form from that callback. |
| Programmatic `hcaptcha.execute(widgetID)` | A `div` with `data-size="invisible"` (or explicit `render` with `size: 'invisible'`) | Your code calls `execute`; the callback (or async `execute` result) continues the flow. The Developer Guide sample `preventDefault`s the button, then `submit()`s the form after solve. |

([Invisible Captcha](https://docs.hcaptcha.com/invisible), extract `.sources/invisible.md`; [Configuration](https://docs.hcaptcha.com/configuration), extract `.sources/configuration.md`; [Developer Guide](https://docs.hcaptcha.com/), extract `.sources/developer-guide-widget.md`)

The Invisible page does not restate that a hidden field is automatically added to the form. The Developer Guide insertion language ("hidden token will automatically be added to your form", "inserted a unique token into your form data") is not qualified by `data-size`. It is the owner for automatic insertion; it is not repeated on the Invisible page.

## Passive and "99.9% Passive"

These are not a different form-field name.

- **Passive**: checkbox is displayed; no visible challenge. Set via the sitekey difficulty. Enterprise only; requires consuming the risk score.
- **Invisible + Passive**: no checkbox and no visible challenge. Enterprise. Lower protection than active challenges.
- **99.9% Passive**: Pro and Enterprise. Selectively challenges users; not a separate widget field.

([Invisible Captcha](https://docs.hcaptcha.com/invisible), extract `.sources/invisible.md`)

## Not stated by the owner pages

- DOM node type of the injected token field (`input` vs `textarea`).
- That the widget also injects `g-recaptcha-response` (switch docs replace that name).
- That a pre-existing hidden `<input>` is required (samples omit it).
- That Invisible button-bind uses ordinary unintercepted Submit (it requires `data-callback`).

## Sources

- Official: [Developer Guide](https://docs.hcaptcha.com/)
- Official: [Configuration](https://docs.hcaptcha.com/configuration)
- Official: [Invisible Captcha](https://docs.hcaptcha.com/invisible)
- Official: [Switch from reCAPTCHA to hCaptcha](https://docs.hcaptcha.com/switch)
- Official: [React](https://docs.hcaptcha.com/integrations/react)
- Official: [Node.js](https://docs.hcaptcha.com/integrations/node)
- Extracts: `.sources/`
