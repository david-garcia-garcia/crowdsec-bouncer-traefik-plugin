## ADDED Requirements

### Requirement: Forced-decision drops use plugin origin
When the bouncer remediates because a configured `crowdsecDecisionHeader` forced `b` or `c`, the `dropped` item SHALL send `origin=plugin:forced_decision`. It MUST NOT reuse `crowdsec`, `cscli`, `CAPI`, `appsec`, `lists:`, or the tech/lapi/appsec failure origins. Ban and captcha remediations still send `remediation=ban` or `remediation=captcha`. A gated-OK captcha that reaches the next handler MUST NOT increment `dropped` for that force.

#### Scenario: Forced ban drop uses plugin origin
- **WHEN** a non-trusted client is banned because `crowdsecDecisionHeader` forced `b`
- **THEN** the `dropped` item has `origin=plugin:forced_decision` and `remediation=ban`

#### Scenario: Forced captcha drop uses plugin origin
- **WHEN** a non-trusted client is shown captcha because `crowdsecDecisionHeader` forced `c` and the gate cookie is not valid
- **THEN** the `dropped` item has `origin=plugin:forced_decision` and `remediation=captcha`
