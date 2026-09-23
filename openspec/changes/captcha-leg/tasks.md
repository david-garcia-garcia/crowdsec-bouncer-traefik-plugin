## 1. Configuration and validation

- [ ] 1.1 Add `CaptchaEnabled` (`captchaEnabled`, default false) and `CaptchaInstanceName` (`captchaInstanceName`) on `Config`. Do not rename `bouncerCaptcha*`.
- [ ] 1.2 Gate owner-style captcha checks (provider, keys, gate secret, loadable template, custom-validate body) on `captchaEnabled`. Ignore subscriber leftover `bouncerCaptcha*`.
- [ ] 1.3 Extend `validateLegOpenVsSubscribe` to captcha: leftover `captchaInstanceName` with bounce and own both false is E2. Do not treat leftover `bouncerCaptcha*` as E2 secrets.
- [ ] 1.4 Change `validateFailureAction` so `captcha` is legal only when the effective captcha instance name is non-empty after owner-fill rules. Dest keys stay `bouncerLapiFailureAction` / `bouncerAppsecFailureAction`.
- [ ] 1.5 Update `zzz_configuration_test.go` (owner vs subscriber, E2/E3 captcha, failure-action instance-name gate, default false).

## 2. Captcha owner (`pkg/captcha`)

- [ ] 2.1 Add `Prepare` that fills empty `captchaInstanceName` to the Traefik name only when `captchaEnabled`.
- [ ] 2.2 Add ownership key (middleware name plus instance-owned captcha knobs). Open + hooks; Sleep/Wake MAY be no-ops. Siteverify `http.Client` Timeout is `BouncerCaptchaSiteverifyHTTPTimeoutSeconds`.
- [ ] 2.3 Lift `remediationCustomHeader` off `Client`. Challenge page and solved redirect take the header name from the Bouncer call site.
- [ ] 2.4 Update `pkg/captcha` tests and any `Client.New` call sites that still pass a header.

## 3. Plugin constructor (`plugin.go`)

- [ ] 3.1 Add `legCaptcha`. Call `captcha.Prepare` after AppSec Prepare. Add captcha cases to `openOwned` / `claimOwned` (do not rewrite into an N-leg registry). Rollback already-published legs when a later claim fails.
- [ ] 3.2 `subscribeCaptcha = bouncerEnabled && captchaInstanceName != ""`. Pass it to `bouncer.New`. `Watch` `alias:captcha:<name>` after New.
- [ ] 3.3 Update `zzz_plugin_test.go` constructor tests for owner, subscriber, holder-with-bounce-off, and collision.

## 4. Bouncer

- [ ] 4.1 Add captcha `atomic.Value`, `ReceiveCaptcha`, and `subscribeCaptcha`. Remove local `captcha.Client.New` from `bouncer.New`.
- [ ] 4.2 Startup-block 503 for an unpublished subscribed captcha name. Startup block off: captcha verdict with empty/invalid loaded client is a ban.
- [ ] 4.3 Write this router's remediation header at captcha call sites. Update `pkg/bouncer/zzz_*.go` (timeout tests construct via owner Open or a test helper, not bounce-only `New`).

## 5. Operator files and e2e

- [ ] 5.1 Set `captchaEnabled: true` on in-repo examples (`examples/captcha/*`, `examples/custom-captcha/*`) and mock/real e2e captcha routes. README names the break (provider-only YAML no longer owns).
- [ ] 5.2 Real compose / labels / file-provider YAML include `captchaEnabled` / `captchaInstanceName`. Captcha-serving Pester route owns captcha.

## 6. Devdocs (implement / devdocsimpact)

- [ ] 6.1 Leave Language/usage folds for implement / `opd-devdocsimpact` (Slot third table, Bouncer third binding, Two configuration axes, captcha no longer per-Bouncer). Do not write packets in propose.
