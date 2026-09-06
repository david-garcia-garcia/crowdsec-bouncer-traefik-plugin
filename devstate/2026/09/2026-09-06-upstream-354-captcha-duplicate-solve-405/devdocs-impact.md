# Devdocs impact
change: redirect-solved-captcha-form-post

## Units
- Captcha remediation — subsystem — `pkg/captcha`, `pkg/bouncer/bouncer.go` captcha grace path, spec `core_plugin_captcha_solved-form-post`

## Findings
- [x] missing-packet  Captcha remediation — no packet; middleware only said templates live on Bouncer
  Taken: `knowledge/devdocs/core_plugin_captcha.md` + `index_core_plugin.md` row
