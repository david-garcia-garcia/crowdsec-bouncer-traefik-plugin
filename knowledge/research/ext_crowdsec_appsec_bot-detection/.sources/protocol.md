---
url: https://docs.crowdsec.net/docs/next/appsec/protocol.md
title: WAF / Bouncer Communication Protocol
fetched: 2026-09-05
authority: official
---

Required headers on the request the bouncer sends to AppSec include X-Crowdsec-Appsec-Ip, -Uri, -Host, -Verb, -Api-Key, -User-Agent, -Http-Version. GET unless original has a body, then POST with that body.

Listener response codes:
- 200: allowed. Body {"action": "allow"}
- 403: rule(s) triggered. Body {"action":"ban","http_status":403} or captcha equivalent, or {"action":"challenge", ...}
- 500: engine error. Bouncer APPSEC_FAILURE_ACTION.
- 401: not authenticated.

Bot detection: 403 with {"action":"challenge"} carries a complete response (body, headers, cookies) the bouncer relays. Exchange continues over internal URLs the component must forward. Full contract is the challenge protocol page.
