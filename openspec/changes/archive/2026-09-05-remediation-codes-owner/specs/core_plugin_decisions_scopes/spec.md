## ADDED Requirements

### Requirement: Decision remediations are decisionscope codes
`pkg/decisionscope` SHALL own the ban, captcha, and none cache payloads as `BannedValue` (`t`), `CaptchaValue` (`c`), and `NoBannedValue` (`f`). `RemediationValue` SHALL map LAPI type `ban` to `BannedValue` and `captcha` to `CaptchaValue`. Callers that compare or store a decision remediation SHALL use those names. Wire values MUST remain `t`, `c`, and `f` so existing Redis and memory entries stay valid.

#### Scenario: LAPI ban still stores t
- **WHEN** a decision type is `ban`
- **THEN** the cached remediation is `t`

#### Scenario: LAPI captcha still stores c
- **WHEN** a decision type is `captcha`
- **THEN** the cached remediation is `c`

#### Scenario: None is f
- **WHEN** a live miss or inactive lookup stores a none payload
- **THEN** the cached value is `f`
