# Turnstile siteverify

How official Cloudflare Turnstile Siteverify accepts `secret`, `response`, and `remoteip`.

Fetched: 2026-09-18.

## POST to Siteverify

Endpoint: `POST https://challenges.cloudflare.com/turnstile/v0/siteverify`. Accepts `application/x-www-form-urlencoded` or `application/json`. Always returns JSON. ([Validate the token](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/), extract `.sources/validate-the-token.md`)

| Parameter | Official status |
| --- | --- |
| `secret` | Required |
| `response` | Required (the widget token) |
| `remoteip` | No (optional). The visitor's IP address. |
| `idempotency_key` | No (optional). A UUID to safely retry validation requests. |

Official examples append `remoteip` when the caller has a value. PHP / C# samples omit the field when the string is empty. Cloudflare's own examples often read `CF-Connecting-IP` or `X-Forwarded-For` inside the application — that is their sample host, not this plugin's owner.

`internal-error` is a retryable Siteverify error code. Official docs say implement retry logic for temporary network issues. They do not require a 400 to the browser on transport failure.

## Sources

- Official: [Validate the token · Cloudflare Turnstile docs](https://developers.cloudflare.com/turnstile/get-started/server-side-validation/)
- Extract: `.sources/validate-the-token.md`
