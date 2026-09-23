## ADDED Requirements

### Requirement: AppSec identity JSON reuses the session marshaler
AppSec reclaim identity JSON SHALL be produced only by the marshaler in `pkg/appsec/session.go`. Implementations MUST NOT reconstruct that payload in `pkg/configuration` or `pkg/bouncer`. That marshaler SHALL keep `scheme` / `host` / `path` / `key` and SHALL rename `tlsCertificateBouncer` / `tlsCertificateBouncerKey` to `tlsClientCertificate` / `tlsClientKey`. Transport fields still spelled `appsecTLSCertificateBouncer` SHALL use `TLSClientCertificate` / `TLSClientKey`. A field-name change SHALL change the hash. A process restart SHALL build a new Client.

#### Scenario: AppSec hash uses session.go only
- **WHEN** two Opens share middleware name and AppSec knobs
- **THEN** both ownership keys come from `pkg/appsec/session.go`
- **AND** no second hash is computed in `configuration` or `bouncer`

## MODIFIED Requirements

### Requirement: AppSec is reclaimed by listener identity
When `appsecEnabled` is true, the owning middleware SHALL reclaim an `appsec.Client` with `reclaim.Open` on the process table (30s grace). The reclaim **ownership** key SHALL be derived from the Traefik middleware name plus AppSec scheme, host, path, resolved key, body limit, TLS material, and `AppsecHTTPTimeoutSeconds`. AppSec instance slot names, `bouncerEnabled`, bounce knobs, LAPI fields, and per-router AppSec failure action MUST NOT be in that key. Two `Open` calls with different middleware names and otherwise identical AppSec knobs SHALL produce two Clients. Two `Open` calls with the same middleware name and identical knobs SHALL Wake the same Client on reload. A change to any keyed AppSec knob SHALL Open a new Client; `AdoptTransport` MUST NOT be the path that applies timeout or TLS changes.

#### Scenario: Two middleware names do not share AppSec
- **WHEN** two owners Open AppSec with different Traefik names and identical URL, key, and body limit
- **THEN** two AppSec Client incarnations exist

#### Scenario: Timeout change is a new Client
- **WHEN** a second Open for the same middleware name changes only `appsecHttpTimeoutSeconds`
- **THEN** the second Open returns a different Client incarnation than the first

#### Scenario: Same name same knobs Wake
- **WHEN** the holder context for an AppSec ownership key is cancelled and a `New` with the same name and knobs runs before grace ends
- **THEN** the same AppSec Client incarnation is returned

### Requirement: Empty AppSec key falls back to LAPI key
`appsec.Prepare` SHALL copy `lapiKey` into `appsecKey` when the AppSec key is empty, and SHALL copy `lapiScheme` into `appsecScheme` when the AppSec scheme is empty. It MUST NOT copy `lapiHttpTimeoutSeconds` into `appsecHttpTimeoutSeconds`. Callers SHALL run `lapi.Prepare` before `appsec.Prepare`.

#### Scenario: Shared bouncer key still works
- **WHEN** the operator sets `lapiKey` and omits `appsecKey` with AppSec enabled
- **THEN** AppSec authenticates with that LAPI key

#### Scenario: AppSec timeout does not copy from LAPI
- **WHEN** `lapiHttpTimeoutSeconds` is 2, `appsecEnabled` is true, and `appsecHttpTimeoutSeconds` is omitted
- **THEN** AppSec timeout stays 10

### Requirement: Zero body limit forwards the full body
When `appsecBodyLimit` is `0`, `Query` SHALL treat the cap as unlimited: it SHALL copy the full readable client body to AppSec and restore that body for origin. It MUST NOT apply a zero-byte read cap that yields an empty body. A positive limit SHALL still cap the copy. The omitted default SHALL remain 10485760.

#### Scenario: Zero limit forwards a POST body
- **WHEN** `appsecBodyLimit` is `0` and the client request has a readable body
- **THEN** AppSec receives that body as POST
- **AND** origin can still read the original body

### Requirement: AppSec transport Timeout is the effective AppSec seconds
AppSec HTTP construct SHALL set `http.Client.Timeout` and the stored timeout seconds from `config.AppsecHTTPTimeoutSeconds`. It MUST NOT read a shared or inherited timeout. Inside `pkg/appsec` the stored field SHALL be `HTTPTimeoutSeconds` (prefix already dropped). `Query` SHALL use that stored client. `AdoptTransport` SHALL keep last-writing that transport on the same Client only when the ownership key is unchanged. The AppSec ownership key SHALL include `AppsecHTTPTimeoutSeconds`. Implementations MUST NOT call `EffectiveHTTPTimeoutSeconds`.

#### Scenario: AppSec timeout change is a new Client
- **WHEN** a later `New` enables AppSec with the same middleware name, URL, key, and body limit and `AppsecHTTPTimeoutSeconds` 30
- **THEN** the stored transport Timeout is 30 seconds
- **AND** a later Open that changes only that knob is a new Client

#### Scenario: Query hang honors the AppSec timeout
- **WHEN** AppSec is opened through `New` or `Open` with `AppsecHTTPTimeoutSeconds` 1 and `bouncerAppsecFailureAction` passthrough
- **AND** `Query` hits a listener that never accepts
- **THEN** `Query` returns a passthrough allow
- **AND** the call finishes well under 10 seconds

#### Scenario: AppSec timeout knobs change the ownership key
- **WHEN** two AppSec Opens share middleware name, URL, key, and body limit and differ only on `appsecHttpTimeoutSeconds`
- **THEN** the ownership keys differ
- **AND** two Client incarnations exist

### Requirement: Client disconnect while buffering is not an AppSec query
When `Query` copies a readable POST, PUT, PATCH, or DELETE body and `io.ReadAll` fails with `context.Canceled`, `context.DeadlineExceeded`, or `io.ErrUnexpectedEOF`, `Query` SHALL return `ErrClientDisconnected` and MUST NOT send a request to the AppSec listener. `bouncerAppsecFailureAction` SHALL NOT change that result. Unclassified body-read errors SHALL keep `appsecQuery:GetBody`. Serving the disconnect (TRACE, optional remediation header, no ban, no origin) is owned by `core_plugin_middleware_bouncer`.

#### Scenario: Canceled body does not reach AppSec
- **WHEN** buffering a readable POST body fails with `context.Canceled`
- **THEN** `Query` returns `ErrClientDisconnected`
- **AND** the AppSec listener is not called
- **AND** `bouncerAppsecFailureAction: ban` does not change that
