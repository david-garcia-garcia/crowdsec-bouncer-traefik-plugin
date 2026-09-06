## 1. Config

- [x] 1.1 Add `CaptchaCustomValidateBody` to `Config` (`json:"captchaCustomValidateBody,omitempty"`), default empty, constants `form` and `json`
- [x] 1.2 `validateCaptcha` rejects unknown values; empty and `form`/`json` pass

## 2. Captcha client

- [x] 2.1 Pass body format into `Client.New`; custom `infoProvider` stores it; built-in providers stay form
- [x] 2.2 `Validate`: `json` POSTs JSON `secret`/`response` with `Content-Type: application/json`; otherwise keep `PostForm`
- [x] 2.3 Decode `success` and close the body as today; do not send `remoteip`

## 3. Bouncer

- [x] 3.1 Pass `config.CaptchaCustomValidateBody` into `captchaClient.New`

## 4. Docs and tests

- [x] 4.1 README + `examples/custom-captcha/README.md`: document `captchaCustomValidateBody`, CapJS JSON + `cap-token`
- [x] 4.2 `pkg/captcha` tests: custom form urlencoded; custom json JSON body and content-type; built-in stays form; missing token / non-POST skip verify
- [x] 4.3 Configuration tests: unknown body rejected; empty and `json` accepted with custom provider
