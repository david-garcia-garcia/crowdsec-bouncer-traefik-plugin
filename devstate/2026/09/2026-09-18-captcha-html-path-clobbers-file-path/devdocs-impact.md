# Devdocs impact
change: captcha-html-path-clobbers-file-path

## Units
- Plugin middleware New — subsystem — knowledge/devdocs/core_plugin_middleware.md (`plugin.go`; spec `core_plugin_middleware_bouncer`)

## Findings
- [x] stale-usage  Plugin middleware New — How-to and Gotchas omitted the HTML-path copy on `prepared` (empty current only; `/captcha.html` is not empty)
