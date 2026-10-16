# Deviations

- [x] taken  keep captchaFormMaxBytes on leftover detection
  Asked: leftover detection is POST contains `crowdsec_captcha_challenge=v1`, with no size named.
  Instead: leftover detection keeps the existing 64KiB peek; over-cap bodies are not leftover forms.
  Owner: `pkg/captcha/form.go` (`captchaFormMaxBytes`, `peekCaptchaFormBody`)
  Why: honouring an uncapped read would drop the live routing promise that detection never costs origin its body; the ask's HTML does not name dropping the cap.
  By: propose
  Requester: not asked
