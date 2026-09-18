## ADDED Requirements

### Requirement: Captcha HTML path aliases only when current path is empty
`New` SHALL copy `CaptchaHTMLFilePath` onto `CaptchaFilePath` only when `CaptchaFilePath` is empty, using the same empty-guard as `BanHTMLFilePath` → `BanFilePath`. When both keys are set, `New` MUST keep `CaptchaFilePath`. Compile and serve SHALL use that field. `New` MUST NOT treat the `/captcha.html` default as empty. `New` MUST NOT remove or rename `CaptchaHTMLFilePath`.

#### Scenario: Both keys set keeps current path
- **WHEN** `New` receives a non-empty `CaptchaFilePath` and a different non-empty `CaptchaHTMLFilePath`
- **THEN** `CaptchaFilePath` stays the current value
- **AND** later compile and serve use that field

#### Scenario: Empty current fills from deprecated
- **WHEN** `New` receives empty `CaptchaFilePath` and non-empty `CaptchaHTMLFilePath`
- **THEN** `CaptchaFilePath` becomes `CaptchaHTMLFilePath`
