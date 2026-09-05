# Codereview

Pin: `origin/master` `2d4acf366cf91884967f91e87a54e7744d62078d`
Command: `git diff origin/master...HEAD -- . ':!devstate' ':!.cursor'`
Head: `24e4dc963b47aebceab298ea18391c8d0210c59b`

## Standards
none

Gotchas pasted: `core_cache_client.md` (no Redis key migration; payloads stay `t`/`c`/`f`/`d`); `core_plugin_decisionscope.md` (ban wins; do not geolocate). Diff keeps wire bytes and lookup merge.

Shotgun-surgery shape (many call-site imports) is the ticket: update every comparer. Commandment Bound the ask / Smallest durable delta endorse it; smell suppressed.

## Spec
none

Requirements walked:
- Decision remediations are decisionscope codes — `pkg/decisionscope/lookup.go` consts + `RemediationValue`; callers use those names.
- Cache payloads are opaque strings — `pkg/cache/cache.go` dropped the four names; `cache_test.go` uses `"t"`/`"c"`/`"f"`.
- Captcha grace-done payload is owned by captcha — `pkg/captcha/captcha.go` `CaptchaDoneValue` (`d`).

## Security
none

No new source or sink. Constants only. Identity still `pkg/ip.GetRemoteIP`. Fail-open / fail-closed paths unchanged.

## Performance
none

No new I/O, loop, collection, or request-path walk. Same string compares.

## Dead
none

Grep `BannedValue` / `CaptchaValue` / `NoBannedValue` / `CaptchaDoneValue` in `*.go` excluding tests: production callers in `lookup.go`, `rangemembership.go`, `bouncer.go`, `connection.go`, `connection_decisions.go`, `captcha.go`. Cache package no longer exports them.

## Applied
none.

## Recorded and skipped
none.
