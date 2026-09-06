# Assessment: upstream#380

- relevant: yes
- kind: feature
- affected: yes
- status: present-unfixed
- proof: none
- recommended-action: fix
- slug: 2026-09-06-upstream-380-trycap-captcha
- rationale: The request is for first-class TryCap (Cap Standalone) captcha support alongside hcaptcha/recaptcha/turnstile. On `master`, `pkg/captcha/captcha.go` only registers those three built-ins plus a `custom` provider whose `Validate` always POSTs `application/x-www-form-urlencoded` via `PostForm`. TryCap Standalone expects JSON `{"secret","response"}` to `/<site_key>/siteverify` and uses the `cap-token` widget field—so it cannot be verified natively today (same gap as upstream #318). Self-hosted captcha is in scope for this product (`examples/custom-captcha/` documents wicketkeeper only); operators currently need an external adapter shim.

## Evidence
- current: pkg/captcha/captcha.go
- current: pkg/configuration/configuration.go
- current: examples/custom-captcha/README.md
- tests: tests/e2e/real/captcha.Tests.ps1
- tests: tests/e2e/mock/scenarios/captcha/run.sh
