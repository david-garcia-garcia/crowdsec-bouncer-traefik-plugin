# Deviations

- [x] taken  keep recaptcha-enterprise on the allowlist
  Asked: eucaptcha beside hcaptcha, recaptcha, turnstile, and custom.
  Instead: those tokens plus dest's recaptcha-enterprise.
  Owner: `pkg/configuration/configuration.go` `validateCaptcha`
  Why: dest already owns that token; dropping it would distort the allowlist this change extends.
  By: propose
  Requester: not asked

- [x] taken  keep stock captcha.html without a hardcoded eu-captcha-response input
  Asked: pairing supplies hidden field eu-captcha-response on the stock page.
  Instead: Widget TokenField is eu-captcha-response; official verify.js injects the input; captcha.html stays unchanged.
  Owner: `captcha.html`
  Why: changing the stock page is out of scope; the widget already writes the field.
  By: propose
  Requester: not asked
