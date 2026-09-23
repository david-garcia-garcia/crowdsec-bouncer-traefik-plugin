# Scope

| Ticket | Demand | In diff | Status |
|--------|--------|---------|--------|
| 2026-09-22-bouncer-instance-severance | Named LAPI and AppSec slots (`crowdsecLapiInstanceName` / `crowdsecAppsecInstanceName`) | `pkg/configuration/configuration.go`; `pkg/instance/tables.go` | OK |
| 2026-09-22-bouncer-instance-severance | Enable flags per leg (`crowdsecLapiEnabled` defaults false); prepopulate omitted instance name only when that leg is owned; subscribe when `enabled` and the name is set; `enabled` does not create a backend | `pkg/configuration/configuration.go` (`PrepopulateInstanceNames`); `plugin.go` (`openAndPublishOwned`, Subscribe) | OK |
| 2026-09-22-bouncer-instance-severance | Bounce switch stays `enabled` (default false); `false` still Opens if this middleware owns a client and calls `next` | `plugin.go` (Open then subscribe only if enabled); `pkg/bouncer/bouncer.go` (`if !b.enabled { next }`) | OK |
| 2026-09-22-bouncer-instance-severance | Late bind: `New` never waits; two optional `atomic.Value` clients; `streamStartupBlock` 503 vs that leg's failure action | `pkg/bouncer/bouncer.go`; `pkg/instance/tables.go` (`Subscribe` never waits) | OK |
| 2026-09-22-bouncer-instance-severance | Reclaim: separate LAPI/AppSec slot tables; ownership Open key is middleware name plus client knobs; slot name, bounce knobs, and `streamStartupBlock` are not in the key | `pkg/lapi/identity.go` (`OwnershipKey`); `pkg/appsec/session.go`; `pkg/instance/tables.go` | OK |
| 2026-09-22-bouncer-instance-severance | Lifecycle logs: backend Create/Close at INFO; Sleep/Wake at DEBUG; bouncer bound/unbound at INFO | `pkg/lapi/client.go`; `pkg/appsec/client.go`; `pkg/instance/tables.go` | OK |
| 2026-09-22-bouncer-instance-severance | Land `knowledge/debt/2026-09-22-stream-startup-block-rethink.md` | `knowledge/debt/2026-09-22-stream-startup-block-rethink.md` | OK |
| 2026-09-22-bouncer-instance-severance | Land `knowledge/debt/2026-09-22-appsec-tls-follows-lapi.md` | `knowledge/debt/2026-09-22-appsec-tls-follows-lapi.md` | OK |

none.
