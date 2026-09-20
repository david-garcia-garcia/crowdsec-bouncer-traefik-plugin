# Devdocs impact
change: captcha-ban-origins

## Units
- CaptchaBanOrigins — subsystem — `pkg/lapi/captcha_ban_origins.go`, public Config `captchaBanOrigins`
- Stream apply — subsystem — `pkg/lapi/client_stream.go` kind mapping on Range/Ip New

## Findings
- [x] missing-packet  CaptchaBanOrigins — no packet; produced `core_plugin_lapi_captcha-ban-origins.md`
- [x] stale-usage  Stream apply — How-to did not name `remediationKindForOrigin` after `MetricsOrigin`
