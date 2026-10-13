---
url: https://docs.eu-captcha.eu/en/integration/backend/ruby/
title: Ruby - Myra EU CAPTCHA Online Help
fetched: 2026-09-24
authority: official
---

SDK result object, not the HTTP schema:

- `train` return value: `true`, `false`, or `nil`.
- `train` gives `true` when the API did not do the applicable verification and forced a positive result. This occurs when the sitekey does not exist, when the secret does not agree with it, or when the protection of the sitekey is off.
- `success?` already reads this flag and gives `false` in this condition.
- For a network error, `train` gives `nil`.
