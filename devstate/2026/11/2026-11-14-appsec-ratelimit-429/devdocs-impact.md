# Devdocs impact
change: appsec-ban-keeps-429

## Units
- Ban page writer — pattern — `pkg/bouncer/bouncer.go` (`handleBanServeHTTP`, `handleBanStatusServeHTTP`, `appsecBanStatusCode`)
- AppSec leg ban handling — subsystem — `pkg/bouncer/bouncer.go` (`applyAppsecServeHTTP`); spec `core_plugin_appsec_bot-detection` "Structured ban keeps the operator ban template"
- Real-stack e2e AppSec fixtures — pattern — `tests/e2e/real/config/` (CrowdSec image, `acquis.yaml`, `appsec-configs/e2e-rate-limit.yaml`)

## Findings
- [x] stale-usage  Ban page writer — `core_plugin_middleware_ban-page` Language, How to use, snippet, Key files, and Gotcha named only `handleBanServeHTTP` / `remediationStatusCode`
- [x] stale-usage  Ban page writer — `index_core_plugin.md` description named only `handleBanServeHTTP`
- [x] stale-usage  AppSec leg ban handling — `core_plugin_appsec` How to use said ban → `handleBanServeHTTP` with the remediation status
- [x] stale-usage  Real-stack e2e AppSec fixtures — `build_e2e_real` Gotchas named CrowdSec `v1.8.0` only and had no `RateLimit()` route note
