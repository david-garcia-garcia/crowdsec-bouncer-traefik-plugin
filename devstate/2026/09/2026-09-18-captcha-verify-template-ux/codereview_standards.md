# Standards

1. [hard] Consume before produce — `pkg/captcha/zzz_siteverify_test.go:48` — `newSolvePOST` is a new helper next to same-package `solverPOST` (`zzz_validate_body_test.go:63`), which already builds the urlencoded `dummy-captcha-response` POST; the bodies differ only by the token (`ok` vs `ok-token`)
   → Delete `newSolvePOST`; call `solverPOST()` and assert `response=ok-token`
   Status: done
   Argument: deleted `newSolvePOST`; callers use `solverPOST()` and assert `response=ok-token`.
2. [hard] Leave a trail — `pkg/captcha/zzz_siteverify_test.go:48` — `newSolvePOST` is a new function with no succinct job comment (`newTestSiteverifyClient` above it has one)
   → Add a one-line comment that it builds the urlencoded solver POST, or drop the helper (finding 1)
   Status: done
   Argument: helper dropped with Standards 1.
3. [hard] Name for the scope — `pkg/configuration/zzz_configuration_test.go:317` — `emptyPath`, `missingFile`, `emptyBan`, and `aloneEmptyPath` are `*Config` values; sibling fixtures in this file use the `cfg` stem for that role (`cfgCaptchaWithProvider`, `cfgAloneMissingCaptchaKeys`)
   → Rename to `cfgEmptyCaptchaPath`, `cfgMissingCaptchaFile`, `cfgEmptyBanPath`, `cfgAloneEmptyCaptchaPath`
   Status: done
   Argument: renamed to `cfgEmptyCaptchaPath`, `cfgMissingCaptchaFile`, `cfgEmptyBanPath`, `cfgAloneEmptyCaptchaPath`.
