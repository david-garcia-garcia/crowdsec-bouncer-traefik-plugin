## REMOVED Requirements

### Requirement: Connection jobs live in named files
**Reason**: AppSec is no longer a same-package file on `package crowdsecconnection`. LAPI named files live in `pkg/lapi` (`core_plugin_lapi_connection`). AppSec lives in `pkg/appsec` (`core_plugin_appsec_client`).
**Migration**: Use those two specs. Do not keep a mixed `pkg/crowdsecconnection` import path.

### Requirement: Exported API stays on the same package
**Reason**: Callers MUST import `pkg/lapi` and `pkg/appsec`. The frozen `pkg/crowdsecconnection` API (including `AppsecQuery` on `CrowdsecConnection`) is the coupling this change removes.
**Migration**: `LiveLookup` on `lapi.Client`; `Query` on `appsec.Client`.
