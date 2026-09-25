# Devdocs impact
change: remediation-match-trace

## Units
- Request-path Trace attributes — subsystem — `knowledge/devdocs/std_go_logger_debug-attrs.md`, spec `std_go_logger_debug-attrs`, `pkg/bouncer/bouncer.go` remediating TRACE
- Header-mapped scope — subsystem — `pkg/decisionscope` `RequestScopeValues` (identity reused; match unchanged)

## Findings
- [x] stale-usage  Request-path Trace attributes — `std_go_logger_debug-attrs` How-to still names cache-hit; snippet omits remediating `scopes` group
- [x] language-gap  Remediating TRACE — `std_go_logger_debug-attrs` has Request-path Trace, no term for remediating TRACE or slog group `scopes`
