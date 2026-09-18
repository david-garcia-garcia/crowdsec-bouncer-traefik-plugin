## ADDED Requirements

### Requirement: Inherit HTTP timeout knobs stay out of LAPI reclaim identity
Stream/alone `SessionKey`, live/none `Key`, and `IdentityHex` MUST NOT include `CrowdsecLapiHTTPTimeoutSeconds`, `CrowdsecAppsecHTTPTimeoutSeconds`, or `CaptchaSiteverifyHTTPTimeoutSeconds`. Composition SHALL reuse those existing owners. Those owners MUST NOT gain timeout knobs or effective seconds.

#### Scenario: Timeout knobs only do not change stream or live keys
- **WHEN** two stream configs share LAPI URL, key, and Redis store parameters and differ only on `HTTPTimeoutSeconds` or any of the three inherit timeout knobs
- **THEN** `SessionKey` is the same
- **AND** `IdentityHex` is the same
- **AND** live/none `Key` is the same
