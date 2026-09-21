## MODIFIED Requirements

### Requirement: AppSec Client is reclaimed by listener identity
`appsec.Open` SHALL run when this middleware `appsecEnabled` is true and it has AppSec secrets. After Open, `New` SHALL publish the Client under `appsecInstance` (`core_plugin_middleware_named-instance`). Public key `appsecEnabled` replaces `appsecEnabled`. Body limit, URL, and TLS keys use the `appsec*` names.

#### Scenario: Disabled AppSec does not Open
- **WHEN** `appsecEnabled` is false
- **THEN** `New` does not reclaim an AppSec Client
