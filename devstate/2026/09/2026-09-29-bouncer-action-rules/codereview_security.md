# Security

1. [judgement] Client-controlled trust — `pkg/configuration/configuration.go:81` — `bouncerActionRules` header predicates can ban or captcha any client who can set the matched header
   Fix: Keep the README warning; do not treat the header as identity
   Status: skipped
   Argument: judgement; dest header trust, README already warns; not applied unattended.
   Quote:
      ```
      BouncerActionRules []httprule.ActionRule `json:"bouncerActionRules,omitempty"`
      ```
