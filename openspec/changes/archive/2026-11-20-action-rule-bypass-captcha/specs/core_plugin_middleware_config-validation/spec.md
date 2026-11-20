## MODIFIED Requirements

### Requirement: Invalid action rules fail ValidateParams
`ValidateParams` SHALL compile `BouncerActionRules` with the shared action-list constructor (predicate compile plus name/action token rules). An omitted or empty list SHALL pass (that setting is off). A row SHALL fail when path, host, headers, and cookies are all absent (omitted or empty after trim / empty map) AND method is any (omitted, empty after trim, or a match-everything pattern such as `.*`). A method-only or host-only row SHALL pass when `name` and `action` are valid. `!!` SHALL fail. A leading `!` with an empty pattern SHALL fail. A method, path, host, header, or cookie pattern that Go `regexp.Compile` rejects SHALL fail.

`name` empty after trim SHALL fail with inner stem `name: empty`. `name` containing `:` SHALL fail with inner stem `name: contains colon`. A duplicate `name` SHALL fail with inner stem `name: duplicate`. Omitted or empty `action` SHALL fail with inner stem `action: empty`. An unknown token SHALL fail with inner stem `action: unknown %q`. A duplicate token SHALL fail with inner stem `action: duplicate`. `ban` with any other token SHALL fail with inner stem `action: ban must be alone`. `captcha` with `bypassCaptcha` SHALL fail with inner stem `action: captcha with bypassCaptcha`. `bypassCaptcha` alone, or with any of `bypass`, `bypassLapi`, `bypassAppsec`, SHALL pass. Inner errors SHALL be index-prefixed `rule %d: …`. `ValidateParams` SHALL wrap `BouncerActionRules: %w`. Captcha with no usable captcha client MUST NOT fail `ValidateParams`.

A `ValidateParams` failure from this rule SHALL cause `plugin.New` to return a nil handler and that error without opening LAPI. `bouncer.New` SHALL compile again to store the compiled list; ValidateParams discards the compiled value. The plugin MUST NOT ignore an invalid pattern. `bouncer.New` MUST NOT invent a second wrap. Leftover `bouncerAppsecBypassRules`, `bouncerLapiBypassRules`, and `bouncerDecisionHeader` MUST NOT be fields on `Config`.

#### Scenario: Empty list passes
- **WHEN** `bouncerActionRules` is omitted or empty
- **THEN** `ValidateParams` returns no error from that field

#### Scenario: Fully empty predicates fail New
- **WHEN** `bouncerActionRules` contains `{name: x, action: [bypass]}` with no predicates
- **THEN** `ValidateParams` returns an error that names `BouncerActionRules`
- **AND** `New` returns a nil handler and that error
- **AND** it does not open LAPI

#### Scenario: Match-everything method with no other predicate fails
- **WHEN** `bouncerActionRules` contains `{name: x, method: ".*", action: [bypass]}`
- **THEN** `ValidateParams` returns an error that names `BouncerActionRules`
- **AND** `New` returns a nil handler and that error

#### Scenario: Method-only rule passes
- **WHEN** `bouncerActionRules` contains `{name: options, method: "^OPTIONS$", action: [bypass]}`
- **THEN** `ValidateParams` returns no error from that field

#### Scenario: Host-only rule passes
- **WHEN** `bouncerActionRules` contains `{name: probe, host: "^probe\\.example$", action: [bypass]}`
- **THEN** `ValidateParams` returns no error from that field

#### Scenario: Invalid path regexp fails New
- **WHEN** `bouncerActionRules` contains `{name: x, path: "(", action: [bypass]}`
- **THEN** `ValidateParams` returns an error that names `BouncerActionRules`
- **AND** `New` returns a nil handler and that error
- **AND** it does not open LAPI

#### Scenario: Empty name fails
- **WHEN** `bouncerActionRules` contains `{path: "^/x$", action: [bypass]}`
- **THEN** `ValidateParams` returns an error that names `BouncerActionRules`
- **AND** the error contains `name: empty`

#### Scenario: Name with colon fails
- **WHEN** `bouncerActionRules` contains `{name: "a:b", path: "^/x$", action: [bypass]}`
- **THEN** `ValidateParams` returns an error that names `BouncerActionRules`
- **AND** the error contains `name: contains colon`

#### Scenario: Duplicate names fail
- **WHEN** `bouncerActionRules` contains two rows with `name: healthz`
- **THEN** `ValidateParams` returns an error that names `BouncerActionRules`
- **AND** the error contains `name: duplicate`

#### Scenario: Empty action fails
- **WHEN** `bouncerActionRules` contains `{name: x, path: "^/x$"}`
- **THEN** `ValidateParams` returns an error that names `BouncerActionRules`
- **AND** the error contains `action: empty`

#### Scenario: Unknown action token fails
- **WHEN** `bouncerActionRules` contains `{name: x, path: "^/x$", action: [pass]}`
- **THEN** `ValidateParams` returns an error that names `BouncerActionRules`
- **AND** the error contains `action: unknown`

#### Scenario: Duplicate action token fails
- **WHEN** `bouncerActionRules` contains `{name: x, path: "^/x$", action: [bypass, bypass]}`
- **THEN** `ValidateParams` returns an error that names `BouncerActionRules`
- **AND** the error contains `action: duplicate`

#### Scenario: Ban mixed with skip fails
- **WHEN** `bouncerActionRules` contains `{name: x, path: "^/x$", action: [ban, bypass]}`
- **THEN** `ValidateParams` returns an error that names `BouncerActionRules`
- **AND** the error contains `action: ban must be alone`

#### Scenario: Ban mixed with captcha fails
- **WHEN** `bouncerActionRules` contains `{name: x, path: "^/x$", action: [ban, captcha]}`
- **THEN** `ValidateParams` returns an error that names `BouncerActionRules`
- **AND** the error contains `action: ban must be alone`

#### Scenario: Captcha mixed with bypassCaptcha fails
- **WHEN** `bouncerActionRules` contains `{name: x, path: "^/x$", action: [captcha, bypassCaptcha]}`
- **THEN** `ValidateParams` returns an error that names `BouncerActionRules`
- **AND** the error contains `action: captcha with bypassCaptcha`

#### Scenario: bypassCaptcha with a leg skip passes
- **WHEN** `bouncerActionRules` contains `{name: api, path: "^/api/", action: [bypassCaptcha, bypassAppsec]}`
- **THEN** `ValidateParams` returns no error for that list

#### Scenario: Captcha without captcha client still passes ValidateParams
- **WHEN** `bouncerActionRules` contains `{name: c, path: "^/x$", action: [captcha]}`
- **AND** `captchaEnabled` is false
- **THEN** `ValidateParams` returns no error from that field

#### Scenario: Valid rules pass
- **WHEN** `bouncerActionRules` contains `{name: healthz, path: "^/healthz$", action: [bypass]}` and `{name: decision-ban, headers: {X-Crowdsec-Decision: "^b$"}, action: [ban]}`
- **THEN** `ValidateParams` returns no error from that field
