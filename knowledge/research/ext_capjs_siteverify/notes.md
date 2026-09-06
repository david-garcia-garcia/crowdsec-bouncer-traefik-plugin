# CapJS siteverify

Cap Standalone server-side token verification HTTP contract for self-hosted Cap (`tiagozip/cap`).

Fetched: 2026-09-06. Official docs: [trycap.dev](https://trycap.dev). Source pin: `github.com/tiagozip/cap@e02138579482c711ee0bb79c7be3486fe0bf3e84:standalone/src/siteverify.js`.

## Endpoint and method

- **Method:** `POST` only. ([quickstart](https://trycap.dev/guide/), extract `.sources/quickstart-guide.md`; [standalone](https://trycap.dev/guide/standalone/), extract `.sources/standalone-guide.md`)
- **URL:** `https://<instance_url>/<site_key>/siteverify`. The site key may also be omitted from the path; Standalone can derive it from the token prefix embedded in `response`. ([source](https://github.com/tiagozip/cap/blob/e02138579482c711ee0bb79c7be3486fe0bf3e84/standalone/src/siteverify.js), extract `.sources/siteverify.js.md`)

## Request encoding and body keys

- **Content-Type:** `application/json` (not urlencoded). ([quickstart](https://trycap.dev/guide/), extract `.sources/quickstart-guide.md`)
- **Required JSON keys:** `secret` (site secret from dashboard) and `response` (widget token). Both are required; missing either yields HTTP 400 `{ "success": false, "error": "Missing required parameters" }`. ([source](https://github.com/tiagozip/cap/blob/e02138579482c711ee0bb79c7be3486fe0bf3e84/standalone/src/siteverify.js), extract `.sources/siteverify.js.md`)
- **`remoteip`:** optional on reCAPTCHA; **ignored by Cap** if sent. Cap docs list only `secret` and `response` as request params. ([migrate-from-recaptcha](https://trycap.dev/guide/alternatives/migrate-from-recaptcha.md), extract `.sources/migrate-from-recaptcha.md`)

Example:

```bash
curl "https://<instance>/<site-key>/siteverify" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{ "secret": "<key_secret>", "response": "<captcha_token>" }'
```

## Response JSON

- **Success:** HTTP 200, `{ "success": true }`. ([quickstart](https://trycap.dev/guide/), extract `.sources/quickstart-guide.md`))
- **Failure:** `{ "success": false, "error": "<string>" }` with HTTP 400/403/404 depending on cause (bad params, bad secret, token not found/expired). Errors use a single `error` string, not reCAPTCHA's `error-codes` array. ([migrate-from-recaptcha](https://trycap.dev/guide/alternatives/migrate-from-recaptcha.md), extract `.sources/migrate-from-recaptcha.md`; [source](https://github.com/tiagozip/cap/blob/e02138579482c711ee0bb79c7be3486fe0bf3e84/standalone/src/siteverify.js), extract `.sources/siteverify.js.md`)
- **No extra success fields:** unlike reCAPTCHA, Cap does not return `challenge_ts`, `hostname`, or v3 `score`. ([migrate-from-recaptcha](https://trycap.dev/guide/alternatives/migrate-from-recaptcha.md), extract `.sources/migrate-from-recaptcha.md`)
- Tokens are **single-use**; re-posting the same token fails after the first successful verify. ([quickstart](https://trycap.dev/guide/), extract `.sources/quickstart-guide.md`))

## Widget token field name

- Default hidden form input / field name: **`cap-token`**. Override with widget attribute `data-cap-hidden-field-name`. ([widget attributes](https://trycap.dev/guide/widget.html), extract `.sources/widget-attributes.md`; [source](https://github.com/tiagozip/cap/blob/e02138579482c711ee0bb79c7be3486fe0bf3e84/widget/src/src/cap.js), extract `.sources/cap-widget-hidden-field.md`)
- In JS (non-form): `solve` event exposes `e.detail.token`. ([quickstart](https://trycap.dev/guide/), extract `.sources/quickstart-guide.md`))
- Migration contrast: reCAPTCHA uses `g-recaptcha-response`; hCaptcha uses `h-captcha-response`. Cap uses `cap-token`. ([migrate-from-recaptcha](https://trycap.dev/guide/alternatives/migrate-from-recaptcha.md), extract `.sources/migrate-from-recaptcha.md`))

## Contrast with reCAPTCHA / hCaptcha / Turnstile / Wicketkeeper

| | reCAPTCHA / hCaptcha / Turnstile siteverify | Cap Standalone `/siteverify` | Wicketkeeper `/v0/siteverify` |
|---|---|---|---|
| Content-Type | `application/x-www-form-urlencoded` (reCAPTCHA migration docs; same family as hCaptcha/Turnstile) | `application/json` | `application/json` |
| Body keys | `secret`, `response`; optional `remoteip` (ignored by Cap) | `secret`, `response` only | `token`, `nonce`, `response` (PoW hash) — not reCAPTCHA-shaped |
| Success field | `success` (boolean) | `success` (boolean) | `success` (boolean) |
| Widget token field | `g-recaptcha-response` / `h-captcha-response` / `cf-turnstile-response` | `cap-token` (default) | custom via `data-input-name` on widget |

reCAPTCHA vs Cap encoding difference is explicit in the official migration guide (urlencoded `URLSearchParams` before, JSON `JSON.stringify` after). ([migrate-from-recaptcha](https://trycap.dev/guide/alternatives/migrate-from-recaptcha.md), extract `.sources/migrate-from-recaptcha.md`)

Wicketkeeper is a different PoW captcha: its siteverify expects the challenge JWT plus PoW `nonce` and hash `response`, not `secret`+`response`. ([Wicketkeeper server README](https://github.com/a-ve/wicketkeeper/blob/main/server/README.md), extract `.sources/wicketkeeper-server-readme.md`)

Cap docs state API-shape compatibility with reCAPTCHA and hCaptcha for migration (same param names, different encoding and endpoint), and with Cloudflare Turnstile for server-side URL/secret swap. ([quickstart](https://trycap.dev/guide/), [Turnstile comparison](https://trycap.dev/guide/alternatives/turnstile.md))

## References

- Official: [Quickstart](https://trycap.dev/guide/), [Cap Standalone](https://trycap.dev/guide/standalone/), [Migrate from reCAPTCHA](https://trycap.dev/guide/alternatives/migrate-from-recaptcha.md), [Widget attributes](https://trycap.dev/guide/widget.html)
- Source: `github.com/tiagozip/cap@e02138579482c711ee0bb79c7be3486fe0bf3e84:standalone/src/siteverify.js`, `widget/src/src/cap.js`
- Contrast: [Wicketkeeper server README](https://github.com/a-ve/wicketkeeper/blob/main/server/README.md)
- Extracts: `.sources/`
