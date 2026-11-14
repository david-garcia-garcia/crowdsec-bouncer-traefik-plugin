# Deviations

- [x] taken  challenge-marker POST goes to the captcha gate after AppSec lets it through
  Asked: an AppSec `captcha` verdict is remediated as a captcha.
  Instead: also route a POST carrying `crowdsec_captcha_challenge=v1` to the captcha gate when AppSec allowed it, so the form can be validated even when the operator's rule does not match the POST.
  Owner: `pkg/bouncer/bouncer.go` (`serveAppSec`), `pkg/captcha/captcha.go` (`HasChallengeMarker`)
  Why: AppSec judges each request alone; without this, a rule that matches the GET but not the form POST forwards the solve to origin and the captcha can never be solved.
  By: explore
  Requester: not asked
