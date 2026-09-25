# Devdocs impact
change: init-log-component

## Units
- NewWithFormat slog output — subsystem — `pkg/logger/logger.go` / `openspec/specs/std_go_logger_slog-output`
- Request-path Trace attributes — pattern — `knowledge/devdocs/std_go_logger_debug-attrs.md` / `openspec/specs/std_go_logger_debug-attrs`
- Trusted-IP Checker — subsystem — `pkg/ip/checker.go` / `knowledge/devdocs/core_plugin_ip.md`

## Findings
- [x] missing-packet  NewWithFormat slog output — no packet; only a How-to mention of spec id `std_go_logger_slog-output` on `std_go_logger_debug-attrs`
- [x] stale-usage  Request-path Trace attributes — `std_go_logger_debug-attrs` How-to names construct-time DEBUG `Bouncer initialized` and omits `forwardedHeadersTrustedIPs` / `clientTrustedIPs`
