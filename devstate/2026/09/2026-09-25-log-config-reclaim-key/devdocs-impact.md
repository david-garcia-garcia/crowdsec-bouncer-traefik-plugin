# Devdocs impact
change: include-log-config-in-captcha-reclaim-key

## Units
- Instance slots — subsystem — `pkg/captcha/session.go` `ownership` / spec `core_plugin_middleware_instance-slots`
- Middleware New — subsystem — `plugin.go` New / captcha Open key wiring (`core_plugin_middleware`)
- Reclaim context lease — pattern — `pkg/reclaim` / `std_go_reclaim` (unchanged table behavior)
- Nested sloggers — pattern — constructor `*slog.Logger` into `captcha.Open` / `std_go_logger_nested` (construction unchanged)

## Findings
- [x] stale-usage  Instance slots — `core_plugin_middleware_instance-slots` Overview omits `logLevel`, `logFilePath`, and `logFormat` from captcha `OwnershipKey`
- [x] stale-usage  Middleware New — `core_plugin_middleware` Captcha Client Language and Gotcha omit `logLevel`, `logFilePath`, and `logFormat`
