# Issues

- [ ] note large  captcha grace UA+protocol binding → optional bind of User-Agent and request Proto on the session
  Why: upstream#353 UPD asked IP+cookie+useragent+protocol. This change ships IP+cookie only. UA churn and HTTP/1 vs HTTP/2 from the same browser would invalidate grace. Risk: copied cookies in another client stack still work for CaptchaGracePeriodSeconds.
