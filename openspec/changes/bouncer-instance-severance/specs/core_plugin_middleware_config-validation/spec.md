## ADDED Requirements

### Requirement: Enable flags and instance names
`ValidateParams` SHALL accept `lapiEnabled` (default true) and `appsecEnabled` (default false). When `lapiEnabled` is true and the middleware has LAPI secrets (key, client cert, or alone CAPI), it SHALL accept Open. When `lapiEnabled` is true, `lapiInstance` is non-empty, and there are no LAPI secrets, it SHALL accept subscribe. When `lapiEnabled` is true with no secrets and empty `lapiInstance`, it SHALL fail. When `lapiEnabled` is false, leftover LAPI secrets or a non-empty `lapiInstance` SHALL fail. The same four cases apply to AppSec with AppSec key as the secret. `bouncerHold` true together with `bouncerEnabled` true SHALL fail. `lapiMode` SHALL be `live`, `stream`, `none`, or `alone` when this middleware Opens LAPI. Public JSON keys SHALL be the domain-prefixed names (`lapi*`, `appsec*`, `bouncer*`); `logLevel`, `logFormat`, `logFilePath`, and `httpTimeoutSeconds` stay. Old keys (`crowdsecMode`, `crowdsecLapiHost`, `enabled`, …) MUST NOT bind.

#### Scenario: Subscribe without a LAPI key
- **WHEN** `lapiEnabled` is true, `lapiInstance` is `shared`, and `lapiKey` is empty
- **THEN** `ValidateParams` returns no error

#### Scenario: Own LAPI missing key fails
- **WHEN** `lapiEnabled` is true, `lapiInstance` is empty, and there are no LAPI secrets
- **THEN** `ValidateParams` returns an error

#### Scenario: Disabled LAPI with leftover key fails
- **WHEN** `lapiEnabled` is false and `lapiKey` is non-empty
- **THEN** `ValidateParams` returns an error

## REMOVED Requirements

### Requirement: Appsec mode without AppSec warns and still starts
`crowdsecMode: appsec` is removed. AppSec-only is `lapiEnabled: false` with `appsecEnabled: true`.
