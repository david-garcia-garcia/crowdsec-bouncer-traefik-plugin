# hCaptcha siteverify

How official hCaptcha `/siteverify` accepts `secret`, `response`, and `remoteip`.

Fetched: 2026-09-18.

## Form POST, not JSON

`https://api.hcaptcha.com/siteverify` expects a URL-encoded form POST. Do not send a JSON body. Do not use GET. ([Developer Guide](https://docs.hcaptcha.com/), extract `.sources/developer-guide-siteverify.md`)

## remoteip is recommended, not required

| POST parameter | Official status |
| --- | --- |
| `secret` | Required |
| `response` | Required (the `h-captcha-response` token) |
| `remoteip` | Recommended. The user's IP address. Not strictly required; providing it improves verification accuracy and enables Enterprise risk scores. |
| `sitekey` | Optional. The sitekey you expect to see. |

The official curl example includes `remoteip`. Error codes include `missing-remoteip` (the parameter is missing) and `invalid-remoteip` (not a valid IP address or blinded value). Official prose still says the field is not strictly required. ([Developer Guide](https://docs.hcaptcha.com/), extract `.sources/developer-guide-siteverify.md`)

## Sources

- Official: [hCaptcha Developer Guide — Verify the User Response Server Side](https://docs.hcaptcha.com/)
- Extract: `.sources/developer-guide-siteverify.md`
