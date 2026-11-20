## ADDED Requirements

### Requirement: A ban-to-captcha edge does not apply on a captcha-bypass request
When the action rules set a captcha-bypass flag for the request (`core_plugin_middleware_bouncer`, "bypassCaptcha lets a request through where a captcha would be served"), an edge `ban: captcha` MUST NOT apply: the stored ban SHALL be remediated as a ban, with the origin of that decision. Otherwise the remap would soften the ban to a captcha and the bypass would then let the request through, which is a ban turned into a pass in two hops. An edge `ban: pass` SHALL still apply. An edge `captcha: pass` SHALL still apply. A stored captcha with no edge is bypassed by the action rule, not by the remap. Both lookup paths (cache lookup and live lookup) SHALL behave the same.

#### Scenario: Remapped ban stays a ban
- **WHEN** `originBasedDecisionRemap` is `{CAPI: {ban: captcha}}` and the stored kind is ban (`t`) origin `CAPI`
- **AND** a matching action row carries `bypassCaptcha`
- **THEN** ServeHTTP remediates as ban

#### Scenario: Same decision without the rule is a captcha
- **WHEN** `originBasedDecisionRemap` is `{CAPI: {ban: captcha}}` and the stored kind is ban (`t`) origin `CAPI`
- **AND** no matching action row carries `bypassCaptcha`
- **THEN** ServeHTTP remediates as captcha (`c`)

#### Scenario: Ban to pass still passes
- **WHEN** `originBasedDecisionRemap` is `{CAPI: {ban: pass}}` and the stored kind is ban (`t`) origin `CAPI`
- **AND** a matching action row carries `bypassCaptcha`
- **THEN** ServeHTTP does not remediate
- **AND** AppSec/next still run
