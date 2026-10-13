# Stateless captcha gate (signed cookie + bind-IP / cookie-only knob)

Close GitHub PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/45 (branch `2026-09-06-upstream-353-captcha-session-cookie`). That PR bound captcha grace to IP plus a random session cookie stored in the shared cache as `{remoteIP}_captcha_{token}`. Do not merge it. Do not continue that session-store design.

New product work (this ticket only):

1. Captcha grace after a successful provider solve MUST be stateless. Issue a signed cookie (HMAC with a server-side secret). The cookie payload MUST include version, issued_at, optional bind-IP flag, and the normalized client IP when bound. Validation: HMAC matches (constant-time), now <= issued_at + CaptchaGracePeriodSeconds, and if bind-IP is on the current GetRemoteIP matches the signed IP (same IPv6 normalization).
2. Public operator knob: bind the gate to IP+cookie, or cookie-only (no IP bind). Cookie-only still requires valid HMAC + expiry.
3. Remove captcha's dependency on the cache system. `pkg/captcha` MUST NOT Set/Get `{ip}_captcha` or `{ip}_captcha_{token}` or any other grace key. After this change, leftover cache grace keys do not count as solved.
4. Do not reuse the captcha provider secretKey as the HMAC secret; derive or add a dedicated plugin secret.
5. Cookie hygiene: HttpOnly; Path=/; SameSite=Lax; MaxAge=grace seconds; Secure iff TLS; no Domain unless already required. Prefer a cookie name, not an X- header the client can forge.

Out of scope (list on requirement.md; do not take):

- Removing Redis from the product / dropping redis cache for decisions / stream lease
- Binding User-Agent or HTTP proto on the cookie
- Changing how decisions are stored (memory vs Redis)
- Merging or continuing PR #45's cache-token session
