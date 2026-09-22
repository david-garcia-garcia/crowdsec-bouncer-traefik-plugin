## REMOVED Requirements

### Requirement: A second different Traefik name fails New
**Reason**: DecisionStore sharing no longer exclusive per Traefik name; isolation is via ownership Open keys and named slots.
**Migration**: Use distinct instance names or distinct LAPI credentials; second publisher on same slot name still fails via instance-slots.

### Requirement: Bouncer does not own the stream
**Reason**: Requirement text moved to MODIFIED below; stream startup block and client binding changed.

## MODIFIED Requirements

### Requirement: Bouncer binds clients through atomic late bind
The per-router bouncer SHALL hold two optional bound clients as `atomic.Value` fields (LAPI and AppSec), each able to hold a typed nil. `ServeHTTP` SHALL `Load` those fields only and MUST NOT resolve instance names, Peek slot tables, or Open clients on the request path. Subscribers MUST NOT Bind reclaim on those clients. The bouncer SHALL read `crowdsecMode` from the loaded LAPI client on each request, not from a copy taken at `New`. When `enabled` is false the handler SHALL call `next` without applying decisions while owners may still Open and publish.

#### Scenario: Nil LAPI client uses failure action for that leg
- **WHEN** the bouncer subscribed to LAPI but the loaded value is empty and `streamStartupBlock` is false
- **THEN** the request uses that router's LAPI failure action for the LAPI leg
- **AND** no panic occurs

#### Scenario: Mode follows published client swap
- **WHEN** a subscriber's bound LAPI client changes from stream to live via Publish
- **THEN** the next request branches on the newly loaded client's mode

### Requirement: Stream startup block guards subscribed backends on the request path
When `streamStartupBlock` is true, before calling `next` or applying decisions the bouncer SHALL check every leg it subscribed to (LAPI and/or AppSec independently). For each subscribed leg, if the loaded client is not published (typed nil), `ServeHTTP` SHALL return HTTP 503 and MUST NOT call `next`. When `streamStartupBlock` is false, a missing subscribed client SHALL use that leg's failure action instead. The check MUST NOT block `New`. A leg the bouncer did not subscribe to is not part of the guard.

#### Scenario: AppSec-only subscriber does not 503 for missing LAPI
- **WHEN** the bouncer subscribes only to AppSec and LAPI is not subscribed
- **THEN** a missing LAPI client does not cause 503 solely for LAPI

#### Scenario: Both legs subscribed one missing yields 503 when block true
- **WHEN** the bouncer subscribes to LAPI and AppSec, `streamStartupBlock` is true, and AppSec is not published
- **THEN** every request returns 503 until AppSec is published

### Requirement: Bouncer does not own the stream ticker
The per-router bouncer SHALL handle request policy (trusted IPs, ban/captcha pages, whether AppSec runs on pass, LAPI failure action, Redis fail-closed, and live-cache TTL) and MUST NOT start a process-wide stream ticker. Stream polling remains on the LAPI Client opened by an owner middleware.

#### Scenario: Second subscriber does not start a second ticker
- **WHEN** two bouncing middlewares subscribe to the same published LAPI stream client
- **THEN** only one stream ticker runs for that client incarnation
