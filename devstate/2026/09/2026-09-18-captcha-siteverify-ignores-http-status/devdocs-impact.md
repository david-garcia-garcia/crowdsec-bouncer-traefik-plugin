# Devdocs impact
change: require-2xx-siteverify-status-before-success

## Units
- Captcha siteverify — subsystem — `pkg/captcha/captcha.go` `Validate` / spec `core_plugin_middleware_captcha-siteverify`

## Findings
- [x] missing-packet  Captcha siteverify — no packet; gate and routing neighbors mention siteverify success, they do not own HTTP acceptance
