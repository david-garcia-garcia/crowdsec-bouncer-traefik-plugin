## ADDED Requirements

### Requirement: HTTP timeout inherit knobs
`Config` SHALL keep public `HTTPTimeoutSeconds` (JSON `httpTimeoutSeconds`, default 10). It SHALL add `CrowdsecLapiHTTPTimeoutSeconds` (`crowdsecLapiHttpTimeoutSeconds`), `CrowdsecAppsecHTTPTimeoutSeconds` (`crowdsecAppsecHttpTimeoutSeconds`), and `CaptchaSiteverifyHTTPTimeoutSeconds` (`captchaSiteverifyHttpTimeoutSeconds`). `CreateConfig` and `configuration.New` SHALL leave those three knobs at 0. `Config` SHALL expose one method `EffectiveHTTPTimeoutSeconds(override int64) int64` that returns `HTTPTimeoutSeconds` when `override == 0` and otherwise returns `override`. The method MUST NOT coerce a negative override to the shared default. `ValidateParams` SHALL reject a new knob less than 0 (`cannot be less than 0`) and SHALL keep rejecting `HTTPTimeoutSeconds` less than 1 (`cannot be less than 1`).

#### Scenario: Omit and zero inherit the shared default
- **WHEN** `HTTPTimeoutSeconds` is 10 and a new knob is 0 or omitted
- **THEN** `EffectiveHTTPTimeoutSeconds` for that knob returns 10
- **AND** `ValidateParams` returns no error for those zeros

#### Scenario: Positive override wins
- **WHEN** `HTTPTimeoutSeconds` is 10 and `CrowdsecAppsecHTTPTimeoutSeconds` is 1
- **THEN** `EffectiveHTTPTimeoutSeconds(CrowdsecAppsecHTTPTimeoutSeconds)` returns 1

#### Scenario: Negative inherit knob is invalid
- **WHEN** `CrowdsecLapiHTTPTimeoutSeconds` is -1
- **THEN** `ValidateParams` returns an error that names `CrowdsecLapiHTTPTimeoutSeconds` and `cannot be less than 0`

#### Scenario: Shared timeout below one stays invalid
- **WHEN** `HTTPTimeoutSeconds` is 0
- **THEN** `ValidateParams` returns an error that names `HTTPTimeoutSeconds` and `cannot be less than 1`
