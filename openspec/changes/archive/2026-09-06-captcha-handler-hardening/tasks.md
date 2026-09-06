## 1. Cache API

- [x] 1.1 Change `cacheInterface.set` and `Client.Set` to return `error`; propagate Redis writer errors; in-memory `localCache.set` returns nil
- [x] 1.2 Update all `Set` call sites to compile (ignore return where behavior unchanged)

## 2. Configuration

- [x] 2.1 When `CaptchaProvider != ""`, require non-empty `CaptchaFilePath` and successful `GetTemplate` in `validateCaptcha` / `ValidateParams`
- [x] 2.2 Add or extend configuration tests for provider-without-path and unreadable template

## 3. Captcha handler

- [x] 3.1 `Client.New` returns `GetTemplate` error; remove nil template at runtime
- [x] 3.2 Thread `remoteIP` into `Validate(r, remoteIP)`; add `remoteip` to siteverify POST body
- [x] 3.3 After successful verify, check `cacheClient.Set` error; on failure log Error and re-render captcha (200), no 302
- [x] 3.4 Introduce retryable-error distinction; map transport/JSON errors to captcha re-render (200), not bare 400
- [x] 3.5 Update bouncer call site for `Validate` signature if needed

## 4. Unit tests

- [x] 4.1 Add `pkg/captcha/captcha_test.go`: Validate success/failure/content-type/network
- [x] 4.2 ServeHTTP grace success and failed cache write (injectable cache stub)
- [x] 4.3 New: built-in provider, custom provider, empty path, unreadable template
- [x] 4.4 Assert siteverify POST body includes `remoteip`
