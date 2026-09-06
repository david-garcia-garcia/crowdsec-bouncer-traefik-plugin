## prepare (2026-09-06)
phase: prepare
findings: qualified-with-gaps (URL match semantics unknown)
fixed: n/a
skipped: n/a

## explore (2026-09-06)
phase: explore
findings: path-exact pass-through; optional CaptchaCustomChallengeURL; HEAD assets pass; AppSec stays on pass path
fixed: n/a
skipped: live wicketkeeper reproduce

## propose (2026-09-06)
phase: propose
findings: new spec core_plugin_captcha_custom-resource-passthrough
fixed: n/a
skipped: n/a

## implement (2026-09-06)
phase: implement
findings: CaptchaCustomChallengeURL + captcha-kind path pass-through
fixed: apply 5889ccb
skipped: Windows logging TempDir cleanup on go test ./...
