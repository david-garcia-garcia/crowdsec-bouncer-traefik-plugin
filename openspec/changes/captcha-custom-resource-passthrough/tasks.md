## 1. Config

- [ ] 1.1 Add `CaptchaCustomChallengeURL` to `Config` (`json:"captchaCustomChallengeUrl,omitempty"`), default `""` in `New()`
- [ ] 1.2 Leave custom-provider validation as the existing four fields (challenge URL optional)
- [ ] 1.3 Document the key in README next to `CaptchaCustomJsURL`

## 2. Captcha Client

- [ ] 2.1 Pass `CaptchaCustomChallengeURL` into `captcha.Client.New`; store parsed JS and challenge paths for custom provider only
- [ ] 2.2 Add a Client method that reports whether `req.URL.Path` equals a stored custom resource path
- [ ] 2.3 Put `ChallengeURL` on the captcha template execute map
- [ ] 2.4 Unit-test path parse: absolute URL, path-only, query ignored, empty/invalid no match, non-custom no match

## 3. Bouncer

- [ ] 3.1 In `handleRemediationServeHTTP`, when kind is captcha and the captcha Client reports a custom resource, call `handleNextServeHTTP` (all methods including HEAD) before HTML or HEAD→ban
- [ ] 3.2 Do not apply that pass-through on ban kind
- [ ] 3.3 Keep using `req.remoteIP`; do not parse `RemoteAddr`
- [ ] 3.4 Unit-test: captcha GET/HEAD matching JS → next; captcha GET other path → captcha HTML; captcha unmatched HEAD → ban; ban GET matching JS → ban

## 4. Example

- [ ] 4.1 Set `captchaCustomChallengeUrl` on `examples/custom-captcha` compose + README
- [ ] 4.2 Use `{{ .ChallengeURL }}` in `examples/custom-captcha/captcha.html`
