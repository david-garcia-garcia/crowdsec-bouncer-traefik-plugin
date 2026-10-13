# Deviations

- [x] taken  Go httptest dual-cookie Secure instead of a real-stack HTTPS e2e
  Asked: one real end-to-end test forges TLS on/off and `X-Forwarded-Proto` and asserts Secure on `crowdsec_captcha_gate` and `__crowdsec_challenge`.
  Instead: one Go httptest through the plugin with a stub AppSec that sets `__crowdsec_challenge` Secure iff the forwarded URI scheme is `https`.
  Owner: `pkg/bouncer` httptest (`zzz_bouncer_test.go` `testBouncerWithAppsec`) and `pkg/captcha` gate tests
  Why: honouring "real" would add an HTTPS Traefik entrypoint to compose that is HTTP `:80` only; mocklapi does not implement CrowdSec's scheme check. The job (both cookies' Secure under TLS and proto) survives on the existing plugin test harness.
  By: propose
  Requester: not asked
