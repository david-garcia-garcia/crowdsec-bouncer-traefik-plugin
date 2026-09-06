## Why

The captcha remediation path can 302 after a successful provider verify even when the grace cache write fails (solve loop), start with a nil template when no path is configured, omit `remoteip` on siteverify, return bare HTTP 400 on provider transport/JSON failures, and has no unit tests for these paths. Operators and end users hit repeat captcha prompts or broken error pages under Redis or provider outages.

## What Changes

- Make grace-period cache write observable; on failure log at Error and re-render the captcha page (200) — do not 302.
- **BREAKING:** Require a loadable captcha template when `CaptchaProvider` is set; `Client.New` returns `GetTemplate` errors; no nil template at runtime.
- Pass bouncer-resolved client IP as `remoteip` on siteverify POST bodies.
- Treat provider transport and JSON parse errors like failed verification: log and serve captcha HTML (200); no bare 400 for retryable failures.
- Change `cache.Client.Set` to return `error` so captcha (and other callers) can observe Redis write failures.
- Add `pkg/captcha/captcha_test.go` covering validate, ServeHTTP grace/write failure, New template paths, and siteverify body.

## Capabilities

### New Capabilities

- `core_plugin_captcha_handler`: Captcha page render, provider verify, grace cache, startup template validation, and retryable-error UX.

### Modified Capabilities

- `core_cache_client_isolated-store`: `Client.Set` returns `error`, propagating Redis writer failures; in-memory `Set` returns nil.

## Impact

- `pkg/captcha/captcha.go` — primary handler changes and tests.
- `pkg/cache/cache.go` — `Set` / internal `set` return `error`.
- `pkg/configuration/configuration.go` — require template when provider set; propagate template load in `ValidateParams`.
- `pkg/bouncer/bouncer.go` — thread `remoteIP` into `Validate` if signature changes (call site only).
