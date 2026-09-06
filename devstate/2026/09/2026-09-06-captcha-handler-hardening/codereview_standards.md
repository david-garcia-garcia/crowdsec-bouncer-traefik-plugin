# Standards

1. [hard] Name for the scope — `pkg/cache/cache.go:241` — `NewFailingSetClient` is a production export whose only caller is `pkg/captcha/captcha_test.go`
   → Rename so the identifier says test (`NewFailingSetClientForTest`) or unexport into `_test.go`
   Status: done
   Argument: renamed to `NewFailingSetClientForTest`; captcha test updated.

2. [hard] Leave a trail — `pkg/captcha/captcha.go:125` — extracted `renderCaptcha` has no method comment
   → Add a succinct job comment on the method
   Status: done
   Argument: added `// renderCaptcha writes the captcha HTML page with HTTP 200.`

3. [judgement] Duplicated Code — `pkg/configuration/configuration.go:323` and `:469` — `CaptchaFilePath` required-when-provider check appears in both `ValidateParams` and `validateCaptcha`
   → Extract one helper if both layers must stay; otherwise document why both are needed
   Status: skipped
   Argument: dual validation layers are intentional (early validateCaptcha + full ValidateParams with template load).
