# Test coverage

1. [hard] Tombstone log assertion — `pkg/bouncer/zzz_ban_template_test.go:104` — `TestNew_bounceOnlyUnusedCaptchaPathDoesNotWarn` read `newTestLogSink` but called `ValidateParams` with `logger.New`, so it could not fail if captcha WARN regressed; bounce-only proof already lives in `zzz_plugin_test.go`
   Fix: Delete the test; keep the plugin-level bounce-only subtest.
   Status: done
   Argument: Removed `TestNew_bounceOnlyUnusedCaptchaPathDoesNotWarn` and unused import.
