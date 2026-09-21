# Scope

| Ticket | Demand | In diff | Status |
|--------|--------|---------|--------|
| 2026-09-21-bouncer-instance-severance | `lapiEnabled` / `appsecEnabled` choose legs | `pkg/configuration/configuration.go`, `plugin.go` | OK |
| 2026-09-21-bouncer-instance-severance | Named `lapiInstance` / `appsecInstance` Open vs subscribe | `pkg/instance`, `plugin.go`, `pkg/bouncer/bouncer.go` | OK |
| 2026-09-21-bouncer-instance-severance | Remove `appsec` mode; AppSec-only via flags | `configuration.go`, README, tests | OK |
| 2026-09-21-bouncer-instance-severance | `bouncerEnabled` / `bouncerHold` split | `configuration.go`, `plugin.go` holdHandler | OK |
| 2026-09-21-bouncer-instance-severance | Non-blocking subscribe; failure actions on Peek miss | `zzz_plugin_test.go`, `bouncer.go` | OK |
| 2026-09-21-bouncer-instance-severance | Domain-prefixed public keys; no old aliases | Config tags, README, e2e fixtures | OK |
| 2026-09-21-bouncer-instance-severance | README dummy-router / one-middleware docs | `README.md`, `docs/modes.md`, examples | OK |
| 2026-09-21-bouncer-instance-severance | Opener-only `lapiScopeHeaders` | `pkg/lapi/session.go`, scope-union spec | OK |

none.
