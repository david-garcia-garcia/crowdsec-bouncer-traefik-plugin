## 1. Cache API

- [ ] 1.1 Change `cacheInterface.set` and `Client.Set` to return `error`; propagate Redis writer errors; in-memory `localCache.set` returns nil
- [ ] 1.2 Update all `Set` call sites to compile (ignore return where behavior unchanged)

## 2. Configuration

- [ ] 2.1 When `CaptchaProvider != ""`, require non-empty `CaptchaFilePath` and successful `GetTemplate` in `validateCaptcha` / `ValidateParams`
- [ ] 2.2 Add or extend configuration tests for provider-without-path and unreadable template

## 3. Captcha handler

- [ ] 3.1 `Client.New` returns `GetTemplate` error; remove nil template at runtime
- [ ] 3.2 Thread `remoteIP` into `Validate(r, remoteIP)`; add `remoteip` to siteverify POST body
- [ ] 3.3 After successful verify, check `cacheClient.Set` error; on failure log Error and re-render captcha (200), no 302
- [ ] 3.4 Introduce retryable-error distinction; map transport/JSON errors to captcha re-render (200), not bare 400
- [ ] 3.5 Update bouncer call site for `Validate` signature if needed

## 4. Unit tests

- [ ] 4.1 Add `pkg/captcha/captcha_test.go`: Validate success/failure/content-type/network
- [ ] 4.2 ServeHTTP grace success and failed cache write (injectable cache stub)
- [ ] 4.3 New: built-in provider, custom provider, empty path, unreadable template
- [ ] 4.4 Assert siteverify POST body includes `remoteip`
