---
url: https://docs.crowdsec.net/docs/next/appsec/bot_detection/challenge_protocol.md
title: Challenge protocol
fetched: 2026-09-05
authority: official
---

Challenge is an extra action next to allow, ban, captcha. AppSec answers the bouncer with HTTP 403 and a JSON envelope: action, http_status, user_body_content, user_headers, user_cookies.

http_status is the code to return to the browser, not the 403 the bouncer received. Defaults to 200 if absent or zero. Not always 200 (e.g. 307 + Location for allowlist-bypass).

Failure behaviour table:

- 200 → allow the request.
- 403, action challenge, non-empty user_body_content → serve the challenge.
- 403, action challenge, empty user_body_content → fail closed (ban).
- 403, any other action → apply that action (ban, captcha, …).
- 403 with empty body → ban.
- 403 with invalid JSON → ban.
- 401, 500, or unexpected status → the component’s configured AppSec failure behaviour (APPSEC_FAILURE_ACTION).

Also: if the challenge cannot be served, treat as ban. Do not leak the AppSec JSON envelope to the browser on a block.
