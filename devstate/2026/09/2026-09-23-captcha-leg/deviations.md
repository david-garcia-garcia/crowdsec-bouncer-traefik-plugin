# Deviations

- [x] taken  dest public keys instead of spec `enabled` / `crowdsecLapiFailureAction`
  Asked: knobs table names bounce `enabled` and failure action `crowdsecLapiFailureAction` (AppSec twin).
  Instead: live dest keys `bouncerEnabled`, `bouncerLapiFailureAction`, `bouncerAppsecFailureAction`. New captcha own-axis keys `captchaEnabled` / `captchaInstanceName`. Owner captcha settings stay `bouncerCaptcha*`.
  Owner: `pkg/configuration/configuration.go`
  Why: dest already renamed those bounce/failure keys in PR 137; honouring the spec spellings would add aliases beside the working surface. Requirement Out of scope already declines renaming dest back.
  By: explore
  Requester: not asked
