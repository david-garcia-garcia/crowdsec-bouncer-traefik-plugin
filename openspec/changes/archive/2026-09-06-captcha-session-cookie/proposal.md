## Why

After a captcha solve, grace is stored only as `{clientIP}_captcha`. Anyone sharing that IP inherits the bypass, and the solver can automate from the same address for the whole grace window. Operators need Cloudflare-like IP-plus-cookie binding so a solved captcha is a session, not an IP allowlist.

## What Changes

- On a valid captcha solve, issue an HttpOnly session cookie and store grace under a cache key that includes that token, not the IP alone.
- On later requests, treat captcha as unsolved unless the request presents a cookie whose token matches a live cache entry for **that** client IP (`pkg/ip.GetRemoteIP`).
- Ignore leftover IP-only `{ip}_captcha` keys after upgrade (those clients re-solve).
- Add unit tests for shared-IP isolation and Check with / without / wrong cookie.
- Do **not** bind user-agent or HTTP protocol in this change. Do **not** add public Traefik config keys. Do **not** change AppSec challenge cookie relay.

## Capabilities

### New Capabilities

- `core_plugin_captcha_session-cookie`: Plugin-native captcha grace is a per-session cache entry keyed by GetRemoteIP plus a cookie token; Check fails without a matching cookie.

### Modified Capabilities

None.

## Impact

- `pkg/captcha` — Set-Cookie on solve; Check reads the cookie and the token-suffixed cache key.
- `pkg/bouncer` — pass `req.Request` into `Check` (IP still `req.remoteIP`).
- Tests under `pkg/captcha`.
- No configuration schema change. No AppSec `UserCookies` change.
