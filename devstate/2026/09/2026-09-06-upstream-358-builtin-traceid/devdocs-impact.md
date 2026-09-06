# Devdocs impact
change: add-remediation-traceid

## Units
- Plugin middleware — subsystem — `knowledge/devdocs/core_plugin_middleware.md` (Bouncer owns ban/captcha pages and the new TraceID)

## Findings
- [x] language-gap  Remediation TraceID — `core_plugin_middleware` has Bouncer/Failure action Language, no term for the generated ban/captcha ID
- [x] stale-usage  Plugin middleware — How-to and Key files do not say Bouncer generates the ID and passes it into captcha; `pkg/bouncer/traceid.go` is missing from Key files
