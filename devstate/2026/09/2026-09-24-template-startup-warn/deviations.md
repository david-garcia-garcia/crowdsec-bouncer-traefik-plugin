# Deviations

- [ ] proposed  captcha owner warns on captcha file; bouncer warns on ban file
  Asked: Check both files when the bouncer is created.
  Instead: `captcha.Client.New` / `Open` warns for the captcha template; `bouncer.New` warns for the ban template.
  Owner: `pkg/captcha/captcha.go` `Client.New`, `pkg/bouncer/bouncer.go` `New`
  Why: honouring the wording adds a `CaptchaFilePath` check to `bouncer.New`, a unit that does not own captcha, and would warn a bounce-only subscriber whose unused default is `/captcha.html`.
  By: explore
  Requester: not asked
