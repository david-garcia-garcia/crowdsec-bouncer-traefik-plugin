# Devdocs impact
change: captcha-handler-hardening

## Units
- Captcha handler — subsystem — `openspec/changes/captcha-handler-hardening/specs/core_plugin_captcha_handler/spec.md`
- Isolated cache Client — subsystem — `knowledge/devdocs/core_cache_client.md`

## Findings
- [x] missing-packet  Captcha handler — no packet; only How-to bullets on middleware and AppSec docs
- [x] stale-usage  Isolated cache Client — `Client.Set` now returns `error`; usage doc did not describe write observability
