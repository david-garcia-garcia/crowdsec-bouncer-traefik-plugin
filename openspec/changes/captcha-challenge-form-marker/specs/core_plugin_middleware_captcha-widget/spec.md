## ADDED Requirements

### Requirement: Shipped challenge HTML includes the leftover-form marker
Every shipped CrowdSec challenge page SHALL include a hidden input whose name is `crowdsec_captcha_challenge` and whose value is `v1`, inside the form that POSTs the challenge. That name and value SHALL be the leftover-form marker leftover detection reads. The pages MUST NOT take that name or value from Config. Stock `captcha.html` SHALL stay one file. A replaced template that omits the input SHALL still solve on the first submit when the provider token is valid.

#### Scenario: Stock captcha.html emits the leftover-form marker
- **WHEN** the bundled `captcha.html` is the challenge page
- **THEN** the form that POSTs the challenge includes a hidden input named `crowdsec_captcha_challenge` with value `v1`

#### Scenario: Example and e2e challenge pages emit the leftover-form marker
- **WHEN** `examples/captcha/captcha.html`, `examples/custom-captcha/captcha.html`, `tests/e2e/real/config/captcha-dummy.html`, `tests/e2e/mock/scenarios/captcha/captcha.html`, or `tests/e2e/mock/scenarios/captcha-ban-origins/captcha.html` is the challenge page
- **THEN** that page's challenge form includes a hidden input named `crowdsec_captcha_challenge` with value `v1`

#### Scenario: Replaced template without the marker still first-solves
- **WHEN** the operator uses a challenge template that omits `crowdsec_captcha_challenge`
- **AND** `Check` is false
- **AND** the POST carries a valid provider token
- **THEN** first-solve still verifies that token, mints the gate cookie, and redirects
