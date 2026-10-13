## 1. Configuration

- [x] 1.1 Add optional `CaptchaCustomChallengeURL` (`json:"captchaCustomChallengeUrl,omitempty"`) on `configuration.Config` and `CreateConfig` default empty
- [x] 1.2 Keep `validateCaptcha` required set as the existing four custom fields; empty challenge URL MUST pass
- [x] 1.3 Add `CustomCaptchaResourcePath` as the one owner of "which configured value names a browser path"
- [x] 1.4 Fold the new key's check into master's `validateEnabledCaptchaSettings`: reject a non-empty custom-provider value that names no absolute path; do not reintroduce `validateConfiguredCaptcha`

## 2. Captcha owners

- [x] 2.1 Pass challenge URL into `captcha.Client.New`; parse JsURL + optional challenge URL once; store exact paths that are non-empty and start with `/` (custom provider only)
- [x] 2.2 Add `IsCustomResourceRequest` (exact `req.URL.Path` match; never `CaptchaCustomValidateURL`)
- [x] 2.3 Add `IsCaptchaFormPost` with its own capped reader: 64KiB, urlencoded + multipart, `PostForm` fast path, `Body` and `ContentLength` restored on a no answer
- [x] 2.4 Keep `captchaResponseFromRequest` as the first-verify reader only; say so in both doc comments
- [x] 2.5 Add `WriteSolvedRedirect` (`302` to `req.URL.String()`, `solved-captcha` header when configured; do not remint cookie or call the provider)
- [x] 2.6 Put `ChallengeURL` on the captcha template execute map, filled for the custom provider only

## 3. Bouncer routing

- [x] 3.1 Rewrite `handleRemediationServeHTTP` captcha branch: drop `Method != HEAD`; order custom-resource → Check+form POST 302 → Check origin → `ServeHTTP`; else ban
- [x] 3.2 Passthrough and Check-true ordinary requests MUST call `handleNextServeHTTP`; ban MUST NOT passthrough
- [x] 3.3 Wire `Check(req.Request, req.remoteIP)` only; no cache grace keys; do not touch `pkg/lapi` or `pkg/reclaim`

## 4. Tests

- [x] 4.1 Check-true captcha-form POST → 302 same URL, origin not called; ordinary POST without response field → origin
- [x] 4.2 Custom JS path and optional challenge path under captcha → origin; same path under ban → ban; prefix / ValidateURL path MUST NOT pass
- [x] 4.3 HEAD + captcha (non-resource) → challenge page asserted positively by `TestHandleRemediationServeHTTP_captchaHEADServesChallengePage`, replacing `TestCaptchaMethodBasedLogic`; custom-resource HEAD still reaches origin
- [x] 4.4 Form detection edge cases: over-cap body restored and reaching origin, multipart form detected, unknown content length, already-parsed `PostForm`
- [x] 4.5 Template renders `ChallengeURL` for a custom provider and empty for a built-in provider
- [x] 4.6 `CustomCaptchaResourcePath` table plus `validateEnabledCaptchaSettings` challenge-URL cases

## 5. Operator surface

- [x] 5.1 `README.md` entry for `CaptchaCustomChallengeURL` beside the other captcha keys, with its default
- [x] 5.2 `examples/custom-captcha`: compose label, `{{ .ChallengeURL }}` in `captcha.html`, README

## 6. Verify

- [x] 6.1 `go build ./...`, `go vet ./...`, `go test ./pkg/... -count=1`, `go test . -count=1`, `golangci-lint run ./...`
- [x] 6.2 Race detector on `./pkg/...` via the `golang:1.22.12` container
- [x] 6.3 Merge `origin/master` and re-run every gate on the merged tree
- [x] 6.4 PR body records that #48 and #50 close in favour of this PR, and the ratified HEAD rule
