## 1. Config

- [ ] 1.1 Add `CaptchaCustomValidateBody` to `Config` (`json:"captchaCustomValidateBody,omitempty"`), default empty, constants `form` and `json`
- [ ] 1.2 `validateCaptcha` rejects unknown values; empty and `form`/`json` pass

## 2. Captcha client

- [ ] 2.1 Pass body format into `Client.New`; custom `infoProvider` stores it; built-in providers stay form
- [ ] 2.2 `Validate`: `json` POSTs JSON `secret`/`response` with `Content-Type: application/json`; otherwise keep `PostForm`
- [ ] 2.3 Decode `success` and close the body as today; do not send `remoteip`

## 3. Bouncer

- [ ] 3.1 Pass `config.CaptchaCustomValidateBody` into `captchaClient.New`

## 4. Docs and tests

- [ ] 4.1 README + `examples/custom-captcha/README.md`: document `captchaCustomValidateBody`, CapJS JSON + `cap-token`
- [ ] 4.2 `pkg/captcha` tests: custom form urlencoded; custom json JSON body and content-type; built-in stays form; missing token / non-POST skip verify
- [ ] 4.3 Configuration tests: unknown body rejected; empty and `json` accepted with custom provider
