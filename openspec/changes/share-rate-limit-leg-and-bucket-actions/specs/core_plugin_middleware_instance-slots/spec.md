## MODIFIED Requirements

### Requirement: Named LAPI and AppSec slots are separate tables
The plugin SHALL maintain named slots for LAPI, AppSec, captcha, ModSec, and the rate limit as five groups on the existing reclaim alias table. A slot is keyed by group plus instance name string. The same instance name MAY exist in more than one group at once. Each slot SHALL record the Traefik middleware name that published it, the current client pointer (or empty), and a subscriber list of `*atomic.Value` targets. Implementations MUST NOT use `atomic.Pointer[T]` or function callbacks for fan-out (Yaegi constraint). Implementations MUST NOT add a second slot table beside reclaim.

#### Scenario: LAPI shared and AppSec shared are independent
- **WHEN** one middleware publishes LAPI instance `shared` and AppSec instance `shared`
- **THEN** both slots exist in their respective groups with the same string name
- **AND** unpublish or Clear on one group does not clear the other group's slot

#### Scenario: Captcha shared and LAPI shared are independent
- **WHEN** one middleware publishes LAPI instance `shared` and captcha instance `shared`
- **THEN** both slots exist in their respective groups with the same string name
- **AND** unpublish or Clear on one group does not clear the other group's slot

#### Scenario: ModSec shared and AppSec shared are independent
- **WHEN** one middleware publishes AppSec instance `shared` and ModSec instance `shared`
- **THEN** both slots exist in their respective groups with the same string name
- **AND** unpublish or Clear on one group does not clear the other group's slot

#### Scenario: Rate-limit shared and captcha shared are independent
- **WHEN** one middleware publishes captcha instance `shared` and rate-limit instance `shared`
- **THEN** both slots exist in their respective groups with the same string name
- **AND** unpublish or Clear on one group does not clear the other group's slot

### Requirement: Lifecycle logs match e2e grep contract
Backend Create/Close at INFO, Sleep/Wake at DEBUG, with stable `msg` values `crowdsec lapi instance .` / `crowdsec appsec instance .` / `crowdsec captcha instance .` / `crowdsec modsec instance .` / `crowdsec ratelimit instance .`, attrs `leg`, `instanceName`, `incarnation`. Bouncer bound and unbound at TRACE with `msg` `crowdsec bouncer bound` / `crowdsec bouncer unbound`, attrs `traefikName`, `leg`, `instanceName`, and `incarnation` when one is known. These lines MUST NOT be emitted on the request path. Every leg SHALL emit the bound and unbound lines on the same transitions. Captcha Sleep/Wake MAY be no-ops when the client has no ticker.

#### Scenario: Replace A by B logs two bound lines
- **WHEN** Publish replaces client A with B on the same slot for a subscriber
- **THEN** logs show bound for A then bound for B without an unbound between them on that subscriber

#### Scenario: Captcha owner logs instance started
- **WHEN** a middleware Opens and publishes a captcha client
- **THEN** logs include `crowdsec captcha instance started` with `leg` `captcha`

#### Scenario: ModSec owner logs instance started
- **WHEN** a middleware Opens and publishes a ModSec client
- **THEN** logs include `crowdsec modsec instance started` with `leg` `modsec`

#### Scenario: Rate-limit owner logs instance started
- **WHEN** a middleware Opens and publishes a rate-limit client under instance name `shared`
- **THEN** logs include `crowdsec ratelimit instance started` with `leg` `ratelimit` and `instanceName` `shared`

#### Scenario: Rate-limit subscriber unbound when the owner goes away
- **WHEN** a subscriber is bound to rate-limit instance `shared` and the owner's client is closed after the table grace
- **THEN** logs include `crowdsec bouncer unbound` with `leg` `ratelimit`, `instanceName` `shared`, and the closed client's `incarnation`

## ADDED Requirements

### Requirement: Rate limit publishes on reclaim group ratelimit
The rate-limit client SHALL be published on the reclaim alias table as group `ratelimit`. An owner (`rateLimitEnabled`) SHALL Open it and `SetAlias` that group; an empty `rateLimitInstanceName` SHALL become the Traefik name only when owned. Without `rateLimitEnabled` a middleware SHALL `ClearPublisher` the group. `bouncerEnabled` plus a `rateLimitInstanceName` SHALL `Watch` only. Exclusive publish, generation-aware Clear, and multi-leg rollback SHALL apply as for the other groups.

#### Scenario: Owner omit fills to Traefik name
- **WHEN** `rateLimitEnabled` is true, `rateLimitInstanceName` is omitted, and the Traefik middleware name is `rl-owner`
- **THEN** the published rate-limit alias is `alias:ratelimit:rl-owner`

#### Scenario: One middleware owns and charges
- **WHEN** one middleware sets `rateLimitEnabled` and `bouncerEnabled` and omits `rateLimitInstanceName`
- **THEN** it publishes its rate-limit client under its own Traefik name
- **AND** it Watches that alias and charges its own buckets

#### Scenario: Subscriber omit does not fill
- **WHEN** `rateLimitEnabled` is false, `bouncerEnabled` is true, and `rateLimitInstanceName` is omitted
- **THEN** the name stays empty
- **AND** the middleware does not Watch the rate-limit group

#### Scenario: Subscribe before rate-limit Publish leaves typed nil
- **WHEN** a bouncer Watches rate-limit name `shared` with no publisher yet
- **THEN** `New` returns successfully
- **AND** the rate-limit bound field holds a typed nil until a later Publish Stores a client

#### Scenario: Rate-limit claim failure rolls back the other legs
- **WHEN** this constructor already published LAPI, captcha, and ModSec
- **AND** its rate-limit claim then fails exclusive publish
- **THEN** `New` returns that error
- **AND** the LAPI, captcha, and ModSec aliases published in that attempt are cleared
- **AND** one ERROR `crowdsec instance name taken` names leg `ratelimit`

#### Scenario: Dropped flag clears the alias
- **WHEN** a reload of middleware `rl-owner` sets `rateLimitEnabled` to false
- **THEN** the alias `alias:ratelimit:rl-owner` is cleared
- **AND** its subscribers receive an empty value
