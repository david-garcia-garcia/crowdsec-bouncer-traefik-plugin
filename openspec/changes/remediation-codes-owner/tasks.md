## 1. Move codes

- [x] 1.1 Add `BannedValue`, `CaptchaValue`, `NoBannedValue` on `pkg/decisionscope` in `lookup.go`; switch that package off `cache.*` remediation names; keep `cache.Client` / `CacheMiss` and the `configuration` import
- [x] 1.2 Add `CaptchaDoneValue` on `pkg/captcha`; stop using `cache.CaptchaDoneValue`
- [x] 1.3 Remove the four consts from `pkg/cache`; keep `CacheMiss` / `CacheUnreachable` and Client Get/Set/Delete/GetMany

## 2. Call sites

- [x] 2.1 `pkg/bouncer` uses decisionscope codes; keep `cache.CacheMiss` / `CacheUnreachable`
- [x] 2.2 `pkg/crowdsecconnection` uses decisionscope codes (including lease `updated`); do not split `connection.go`
- [x] 2.3 Tests: `pkg/decisionscope`, `pkg/bouncer`, `pkg/crowdsecconnection`, `plugin_test.go` compare against the new owners
- [x] 2.4 `pkg/cache` tests use opaque string literals

## 3. Docs

- [x] 3.1 Update `knowledge/devdocs/core_plugin_decisionscope.md` so ban/captcha/none codes are decisionscope
- [x] 3.2 Update `knowledge/devdocs/core_cache_client.md` so the store is opaque strings; captcha owns `d`

## 4. Verify

- [x] 4.1 `go test ./pkg/cache/ ./pkg/decisionscope/ ./pkg/captcha/ ./pkg/bouncer/ ./pkg/crowdsecconnection/ ./`
