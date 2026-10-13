## ADDED Requirements

### Requirement: Captcha publishes on reclaim group captcha
The plugin SHALL publish captcha on the existing reclaim alias table as group `captcha` (`alias:captcha:<name>`). It MUST NOT add a second slot table or a parallel publish API. An owning middleware (`captchaEnabled`) SHALL Open a captcha client and `SetAlias` that group. A bouncing middleware (`bouncerEnabled` and a non-empty captcha instance name) SHALL `Watch` only. `New` MUST NOT wait for a captcha publisher. The same instance name string MAY exist in the LAPI, AppSec, and captcha groups at once. Exclusive publish, generation-aware Clear, and multi-leg rollback SHALL apply to captcha the same way they apply to LAPI and AppSec.

#### Scenario: Captcha shared is independent of LAPI shared
- **WHEN** one middleware publishes LAPI instance `shared` and captcha instance `shared`
- **THEN** both aliases exist with the same string name in different groups
- **AND** unpublish or Clear on LAPI does not clear the captcha alias

#### Scenario: Subscribe before captcha Publish leaves typed nil
- **WHEN** a bouncer Watches captcha name `shared` with no publisher yet
- **THEN** `New` returns successfully
- **AND** the captcha bound field holds a typed nil until a later Publish Stores a client

### Requirement: Empty captcha instance name fills only when owned
When `captchaEnabled` is true and the trimmed `captchaInstanceName` is empty, `Prepare` SHALL set the instance name to this middleware's Traefik name. When `captchaEnabled` is false, an empty name SHALL stay empty. The ownership Open key SHALL be the middleware name plus instance-owned captcha knobs (provider, keys, files, timeouts, template, gate, custom paths). Slot name, `bouncerEnabled`, failure actions, remediation header, and `bouncerStartupBlock` MUST NOT be in that key.

#### Scenario: Owner omit fills to Traefik name
- **WHEN** `captchaEnabled` is true and `captchaInstanceName` is omitted
- **AND** the Traefik middleware name is `cs-owner`
- **THEN** the published captcha alias is `alias:captcha:cs-owner`

#### Scenario: Subscriber omit does not fill
- **WHEN** `captchaEnabled` is false, `bouncerEnabled` is true, and `captchaInstanceName` is omitted
- **THEN** the name stays empty
- **AND** the middleware does not Watch captcha

## MODIFIED Requirements

### Requirement: Named LAPI and AppSec slots are separate tables
The plugin SHALL maintain named slots for LAPI, AppSec, and captcha as three groups on the existing reclaim alias table. A slot is keyed by group plus instance name string. The same instance name MAY exist in more than one group at once. Each slot SHALL record the Traefik middleware name that published it, the current client pointer (or empty), and a subscriber list of `*atomic.Value` targets. Implementations MUST NOT use `atomic.Pointer[T]` or function callbacks for fan-out (Yaegi constraint). Implementations MUST NOT add a second slot table beside reclaim.

#### Scenario: LAPI shared and AppSec shared are independent
- **WHEN** one middleware publishes LAPI instance `shared` and AppSec instance `shared`
- **THEN** both slots exist in their respective groups with the same string name
- **AND** unpublish or Clear on one group does not clear the other group's slot

#### Scenario: Captcha shared and LAPI shared are independent
- **WHEN** one middleware publishes LAPI instance `shared` and captcha instance `shared`
- **THEN** both slots exist in their respective groups with the same string name
- **AND** unpublish or Clear on one group does not clear the other group's slot

### Requirement: Lifecycle logs match e2e grep contract
Backend Create/Close at INFO, Sleep/Wake at DEBUG, with stable `msg` values `crowdsec lapi instance …` / `crowdsec appsec instance …` / `crowdsec captcha instance …`, attrs `leg`, `instanceName`, `incarnation`. Bouncer bound/unbound at INFO with `msg` `crowdsec bouncer bound` / `crowdsec bouncer unbound`, attrs `traefikName`, `leg`, `instanceName`, `incarnation`. These lines MUST NOT be emitted on the request path. Captcha Sleep/Wake MAY be no-ops when the client has no ticker.

#### Scenario: Replace A by B logs two bound lines
- **WHEN** Publish replaces client A with B on the same slot for a subscriber
- **THEN** logs show bound for A then bound for B without an unbound between them on that subscriber

#### Scenario: Captcha owner logs instance started
- **WHEN** a middleware Opens and publishes a captcha client
- **THEN** logs include `crowdsec captcha instance started` with `leg` `captcha`
