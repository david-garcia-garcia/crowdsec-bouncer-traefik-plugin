## REMOVED Requirements

### Requirement: Forced-decision drops use plugin origin
**Reason**: `bouncerDecisionHeader` is deleted. Applied plugin ban/captcha from a rule uses `plugin:rules:<name>`.
**Migration**: `cscli metrics show bouncers` origin rows for this path are `plugin:rules:<name>`. `plugin:forced_decision` is no longer emitted.

## ADDED Requirements

### Requirement: Action-rule drops use plugin origin
When the bouncer remediates because a matching `bouncerActionRules` row applied ban or captcha, the `dropped` item SHALL send `origin=plugin:rules:<name>` of the first matching row of that winning kind. It MUST NOT reuse `crowdsec`, `cscli`, `CAPI`, `appsec`, `lists:`, `plugin:forced_decision`, or the tech/lapi/appsec failure origins. Ban and captcha remediations still send `remediation=ban` or `remediation=captcha`. A skip-to-next MUST NOT increment `dropped`. A gated-OK captcha that reaches the next handler MUST NOT increment `dropped` for that rule. LAPI, AppSec, and fail-closed drops that prevail over a captcha rule SHALL keep that leg's origin, not `plugin:rules:`. An unusable captcha client on a captcha rule SHALL still send `origin=plugin:rules:<name>` with `remediation=ban`.

#### Scenario: Action-rule ban drop uses plugin origin
- **WHEN** a non-trusted client is banned because a matching action rule applied ban
- **THEN** the `dropped` item has `origin=plugin:rules:<name>` of that ban row and `remediation=ban`

#### Scenario: Action-rule captcha drop uses plugin origin
- **WHEN** a non-trusted client is shown captcha because a matching action rule applied captcha and the gate cookie is not valid
- **THEN** the `dropped` item has `origin=plugin:rules:<name>` of that captcha row and `remediation=captcha`

#### Scenario: Skip does not drop
- **WHEN** a matching action rule skips both legs and no captcha or ban is applied
- **THEN** the next usage-metrics POST does not include a `dropped` item for that skip

#### Scenario: Captcha rule lost to LAPI keeps LAPI origin
- **WHEN** a captcha rule matched and LAPI lookup is ban
- **THEN** the `dropped` item has the LAPI origin and `remediation=ban`
- **AND** it does not use `plugin:rules:`
