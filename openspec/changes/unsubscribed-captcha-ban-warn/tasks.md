## 1. WARN on unsubscribed captcha kind

- [ ] 1.1 In `pkg/bouncer/bouncer.go` `handleRemediationServeHTTP`, when kind is captcha and `!b.subscribeCaptcha`, emit WARN `crowdsec bouncer captcha unsubscribed` with `leg` `captcha` and `instanceName` `b.captchaInstanceName`, then the existing ban. Do not emit `ip`. Do not call `GetRemoteIP`. Do not add a `Once` field.
- [ ] 1.2 Do not WARN when `subscribeCaptcha` is true (nil or `!Valid` stay on the existing ban; startup-block stays 503 plus `crowdsec bouncer backend missing`). Do not change `plugin.go` subscribe gate.

## 2. Tests

- [ ] 2.1 Add bounce-only captcha-kind coverage that asserts ban plus WARN stem, `leg=captcha`, empty `instanceName`, and no `ip`. Capture logs with `newTestLogSink`. Assert two remediating requests emit the WARN twice.
- [ ] 2.2 Cover forced header `c` on an unsubscribed router when lookup is not ban: ban plus the same WARN.
- [ ] 2.3 Assert subscribed-unpublished (`TestNew_CaptchaSubscriberBeforePublishBans` / Blocks, or a `pkg/bouncer` sibling) does not emit `crowdsec bouncer captcha unsubscribed`. Startup-block on still 503 plus `crowdsec bouncer backend missing`.
- [ ] 2.4 Run `go test ./pkg/bouncer/ . -count=1` for the captcha-kind and constructor tests this change touches.

## 3. Leave neighbors

- [ ] 3.1 Do not change `ValidateParams` failure-action `captcha` (instance name still required). Do not WARN on AppSec JSON `action: captcha`. Do not write `knowledge/devdocs` this apply.
