## Why

After a client solves captcha, a second browser tab that still POSTs the captcha form is forwarded to origin with POST because grace cache (`remoteIP+"_captcha"`) skips `captcha.Client.ServeHTTP`. GET-only origins (for example Laravel) then return 405. The first successful verify already redirects with `StatusFound`; the grace path must do the same for that form POST.

## What Changes

- When captcha remediation is in effect and grace `Check` is true, intercept POST requests that carry the configured captcha provider response field and redirect like the first successful verify (`StatusFound` to the request URL, `solved-captcha` remediation header when configured).
- Leave GET and ordinary origin POSTs (no provider response field) on the existing pass path (`handleNextServeHTTP`).
- Restore `req.Body` when the detector reads a POST and does not intercept, so origin and AppSec still see the payload.
- Use `clientRequest.remoteIP` for the grace key. Do not re-parse `RemoteAddr`.
- Unit tests for detection (built-in and custom field names) and for bouncer grace POST → 302 vs ordinary POST → `next` with body intact.
- **Not BREAKING.** No new public Traefik config keys. Bundled `captcha.html` stays as-is.

## Capabilities

### New Capabilities

- `core_plugin_captcha_solved-form-post`: already-solved captcha form POST redirects instead of being forwarded to origin.

### Modified Capabilities

None.

## Impact

- `pkg/captcha/captcha.go` (detect configured provider response field; keep first-solve redirect as the template)
- `pkg/bouncer/bouncer.go` (`handleRemediationServeHTTP` grace branch)
- Tests under `pkg/captcha/` and `pkg/bouncer/`
- No public config, no Redis key shape change (grace key `remoteIP+"_captcha"` already exists)
