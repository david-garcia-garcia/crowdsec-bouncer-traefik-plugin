# Devdocs impact
change: serialize-stream-poll

## Units
- LAPI Client stream poller — subsystem — `pkg/lapi` (`handleStreamTicker`, `crowdsecQuery`)
- Plugin middleware New — subsystem — `knowledge/devdocs/core_plugin_middleware.md`

## Findings
- [x] stale-usage  Plugin middleware New — gotcha for one in-flight stream poll / TryLock skip / HTTPTimeoutSeconds was missing; produced on `core_plugin_middleware.md` during implement
