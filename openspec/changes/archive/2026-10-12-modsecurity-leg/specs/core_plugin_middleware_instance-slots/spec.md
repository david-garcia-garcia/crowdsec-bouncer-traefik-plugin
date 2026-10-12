## ADDED Requirements

### Requirement: ModSec publishes on reclaim group modsec
The plugin SHALL publish ModSec on the existing reclaim alias table as group `modsec` (`alias:modsec:<name>`). It MUST NOT add a second slot table or a parallel publish API. An owning middleware (`modsecEnabled`) SHALL Open a ModSec client and `SetAlias` that group. A bouncing middleware (`bouncerEnabled` and a non-empty ModSec instance name) SHALL `Watch` only. `New` MUST NOT wait for a ModSec publisher. The same instance name string MAY exist in the LAPI, AppSec, captcha, and ModSec groups at once. Exclusive publish, generation-aware Clear, and multi-leg rollback SHALL apply to ModSec the same way they apply to LAPI, AppSec, and captcha. Captcha-claim failure SHALL also `ClearPublisher` ModSec when this constructor already published it.

#### Scenario: ModSec shared is independent of AppSec shared
- **WHEN** one middleware publishes AppSec instance `shared` and ModSec instance `shared`
- **THEN** both aliases exist with the same string name in different groups
- **AND** unpublish or Clear on AppSec does not clear the ModSec alias

#### Scenario: Subscribe before ModSec Publish leaves typed nil
- **WHEN** a bouncer Watches ModSec name `shared` with no publisher yet
- **THEN** `New` returns successfully
- **AND** the ModSec bound field holds a typed nil until a later Publish Stores a client

#### Scenario: Captcha claim failure rolls back ModSec
- **WHEN** this constructor already published ModSec
- **AND** captcha claim then fails exclusive publish
- **THEN** `New` returns that error
- **AND** the ModSec alias published in that attempt is cleared

## MODIFIED Requirements

### Requirement: Named LAPI and AppSec slots are separate tables
The plugin SHALL maintain named slots for LAPI, AppSec, captcha, and ModSec as four groups on the existing reclaim alias table. A slot is keyed by group plus instance name string. The same instance name MAY exist in more than one group at once. Each slot SHALL record the Traefik middleware name that published it, the current client pointer (or empty), and a subscriber list of `*atomic.Value` targets. Implementations MUST NOT use `atomic.Pointer[T]` or function callbacks for fan-out (Yaegi constraint). Implementations MUST NOT add a second slot table beside reclaim.

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

### Requirement: Lifecycle logs match e2e grep contract
Backend Create/Close at INFO, Sleep/Wake at DEBUG, with stable `msg` values `crowdsec lapi instance .` / `crowdsec appsec instance .` / `crowdsec captcha instance .` / `crowdsec modsec instance .`, attrs `leg`, `instanceName`, `incarnation`. Bouncer bound and unbound at TRACE with `msg` `crowdsec bouncer bound` / `crowdsec bouncer unbound`, attrs `traefikName`, `leg`, `instanceName`, and `incarnation` when one is known. These lines MUST NOT be emitted on the request path. Captcha Sleep/Wake MAY be no-ops when the client has no ticker.

#### Scenario: Replace A by B logs two bound lines
- **WHEN** Publish replaces client A with B on the same slot for a subscriber
- **THEN** logs show bound for A then bound for B without an unbound between them on that subscriber

#### Scenario: Captcha owner logs instance started
- **WHEN** a middleware Opens and publishes a captcha client
- **THEN** logs include `crowdsec captcha instance started` with `leg` `captcha`

#### Scenario: ModSec owner logs instance started
- **WHEN** a middleware Opens and publishes a ModSec client
- **THEN** logs include `crowdsec modsec instance started` with `leg` `modsec`

### Requirement: Client remembers last published slot for rename Wake
An owning LAPI, AppSec, captcha, or ModSec Client SHALL store the instance name it last published. On Wake when the configured instance name differs, the Client SHALL unpublish the stored name (only if it is still publisher and `current` is this Client) before publishing the new name. Sleep SHALL leave the stored name for the following Wake.

#### Scenario: Same Client new slot name unbinds old subscribers first
- **WHEN** a Woken Client republishes under a new instance name without a new reclaim key
- **THEN** subscribers of the old name receive unbound then subscribers of the new name receive bound
- **AND** no second `instance started` log for the same incarnation
