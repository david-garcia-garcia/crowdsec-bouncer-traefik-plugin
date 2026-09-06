# Devdocs impact
change: captcha-session-cookie

## Units
- Plugin-native captcha — subsystem — `pkg/captcha`
- Isolated cache Client — subsystem — `pkg/cache` (captcha session keys)

## Findings
- [x] missing-packet  Plugin-native captcha — no packet; only AppSec challenge docs mention `pkg/captcha`
  Produced: `knowledge/devdocs/core_plugin_captcha.md`
- [x] stale-usage  Isolated cache Client — How-to lists logical keys as client IP, `scope:value`, and `range-index`; captcha grace is now `{remoteIP}_captcha_{token}`
  Produced: `knowledge/devdocs/core_cache_client.md` How-to and Gotchas
