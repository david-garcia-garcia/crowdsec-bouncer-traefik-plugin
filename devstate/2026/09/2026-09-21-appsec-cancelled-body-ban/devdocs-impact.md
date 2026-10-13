# Devdocs impact
change: 2026-09-21-appsec-cancelled-body-ban

## Units
- AppSec query / FailureAction — subsystem — `knowledge/devdocs/core_plugin_appsec.md`

## Findings
- [x] stale-usage  AppSec query / FailureAction — `core_plugin_appsec` How-to and Gotchas listed FailureAction for 500, unreachable, unreadable H2/H3, and AppSec response-body io only; omitted client body dropped vs unclassified `GetBody`
- [x] language-gap  AppSec query / FailureAction — `core_plugin_appsec` had no Language term for client body dropped (`errClientBodyDropped` / `appsecQuery:clientBodyDropped`)
