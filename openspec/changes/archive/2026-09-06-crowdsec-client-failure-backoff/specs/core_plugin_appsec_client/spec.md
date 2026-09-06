## MODIFIED Requirements

### Requirement: AppSec is reclaimed by listener identity
When `crowdsecAppsecEnabled` is true, `New` SHALL reclaim an `appsec.Client` with `reclaim.OpenWithGrace` and a 30s grace. The reclaim key SHALL be derived from AppSec scheme, host, path, key, TLS, body limit, HTTP timeout, and the three AppSec failure-backoff knobs (`appsecFailureBackoffTimeout`, `appsecFailureBackoffBucketWindow`, `appsecFailureBackoffBucketThreshold`). Middleware name, `next`, templates, trusted IPs, Enabled, LAPI fields, and `crowdsecAppsecFailureAction` MUST NOT be in that key. The create func SHALL return `*reclaim.Wrapped`. `Close` SHALL release idle AppSec HTTP connections.

#### Scenario: Two routers share one AppSec listener
- **WHEN** two `New` calls enable AppSec with the same AppSec URL, key, TLS, HTTP timeout, and AppSec backoff knobs, and live constructor contexts
- **THEN** both bouncers use the same `appsec.Client` incarnation

#### Scenario: Different AppSec hosts are isolated
- **WHEN** two `New` calls enable AppSec with different AppSec hosts
- **THEN** two AppSec client incarnations exist

#### Scenario: Different AppSec backoff knobs are isolated
- **WHEN** two `New` calls enable AppSec with the same AppSec URL and key and different `appsecFailureBackoffThreshold`
- **THEN** two AppSec client incarnations exist
