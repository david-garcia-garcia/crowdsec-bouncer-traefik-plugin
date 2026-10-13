# reCAPTCHA siteverify

How official Google reCAPTCHA `/siteverify` accepts `secret`, `response`, and `remoteip`.

Fetched: 2026-09-18.

## POST to siteverify

URL: `https://www.google.com/recaptcha/api/siteverify`. Method: POST. ([Verifying the user's response](https://developers.google.com/recaptcha/docs/verify), extract `.sources/verifying-the-users-response.md`)

| POST parameter | Official status |
| --- | --- |
| `secret` | Required |
| `response` | Required (the user response token) |
| `remoteip` | Optional. The user's IP address. |

The official page does not require `remoteip`. It does not define a missing-remoteip error. Tokens are single-use and expire after two minutes.

## Sources

- Official: [Verifying the user's response | reCAPTCHA](https://developers.google.com/recaptcha/docs/verify)
- Extract: `.sources/verifying-the-users-response.md`
