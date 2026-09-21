# Devdocs impact
change: captcha-ban-origins

## Units
- BanToCaptchaOrigins — subsystem — `pkg/lapi/ban_to_captcha_origins.go`, public Config `banToCaptchaOrigins`
- Stream apply — subsystem — `pkg/lapi/client_stream.go` kind mapping on Range/Ip New

## Findings
- [x] missing-packet  BanToCaptchaOrigins — no packet; produced `core_plugin_lapi_ban-to-captcha-origins.md`
- [x] stale-usage  Stream apply — How-to did not name `remediationKind` after `MetricsOrigin`
