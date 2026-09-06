# Code review
pin: origin/master...HEAD
exclude: devstate/, .cursor/

## Standards
1. [judgement] Duplicated Code — `pkg/configuration/configuration_test.go:8` and `pkg/crowdsecconnection/tls_test.go:12` — `validPEM` is copied so `validateParamsTLS` and TLS construction tests can each parse a CA
   → Leave; packages cannot share an unexported test fixture without a new test helper package this change does not need

## Spec
none

Walked:
- Traefik Config stays the public plugin bag — `pkg/configuration/config.go` Config JSON tags; `plugin.go` CreateConfig unchanged
- File secrets and templates stay on the Config package — `secrets.go` GetVariable, `template.go` GetTemplate
- LAPI and AppSec HTTP use Config TLS fields at client construction — `pkg/crowdsecconnection/tls.go` + `connection.go` New

## Security
none

TLS construction, file-secret reads, and InsecureSkipVerify are the same operator-controlled paths as dest master, moved not widened.

## Performance
none

No new unbounded request-path work. Captcha e2e wait is test-only.

## Dead
none

Grep: `getTLSConfigCrowdsec` is called from `connection.go` New; `getTLSConfig` from that builder; `GetVariable` / `GetTemplate` / `ValidateParams` / `New` / `EffectiveFailureAction` have production callers. `configuration.GetTLSConfigCrowdsec` was deleted.

Standards: 1 finding, worst: Duplicated Code validPEM (judgement)
Spec: 0 findings, worst: none
Security: 0 findings, worst: none
Performance: 0 findings, worst: none
Dead: 0 findings, worst: none

## Applied
none.

## Recorded and skipped
- Standards 1: test-only PEM fixture copy; Bound the ask forbids a new shared test package
