# Dead

1. [hard] Test-only new symbol — `pkg/cache/cache.go:241` — `NewFailingSetClient` has no production callers (grep: only `pkg/captcha/captcha_test.go`)
   → Rename with `ForTest` suffix or move stub into test package
   Status: done
   Argument: renamed to `NewFailingSetClientForTest` (same fix as Standards #1).
