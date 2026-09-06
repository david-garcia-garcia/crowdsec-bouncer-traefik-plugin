# Performance

1. [hard] Unbounded payload — `pkg/captcha/captcha.go:161-170` — `readAndRestoreBody` uses `io.ReadAll(r.Body)` with no byte cap; called from `IsCaptchaFormPost` on every POST while captcha grace is active (`pkg/bouncer/bouncer.go:294-297`), so heap work grows with request body size
   → Bound bytes before read (e.g. `io.LimitReader` with a documented max, matching the tree’s existing body-limit pattern in AppSec)
   Status: done
   Argument: LimitReader captchaFormMaxBytes (64KiB); skip parse when ContentLength is larger; restore peeked bytes via MultiReader. SHA 9373e6e.
