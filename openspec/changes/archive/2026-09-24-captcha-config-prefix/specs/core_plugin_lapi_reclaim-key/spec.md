## MODIFIED Requirements

### Requirement: Inherit HTTP timeout knobs stay out of LAPI store identity
`SessionHex` MUST NOT include `LapiHTTPTimeoutSeconds`, `AppsecHTTPTimeoutSeconds`, or `CaptchaSiteverifyHTTPTimeoutSeconds`. The LAPI ownership Open key SHALL include `LapiHTTPTimeoutSeconds` (the stored knob, not an inherited effective value). AppSec and captcha timeout knobs MUST NOT enter the LAPI ownership key. Implementations MUST NOT add a second timeout hash beside `pkg/lapi/identity.go`.

#### Scenario: Timeout knobs do not change SessionHex
- **WHEN** two stream configs share LAPI URL, key, and Redis store parameters and differ only on `lapiHttpTimeoutSeconds`
- **THEN** `SessionHex` is the same
- **AND** the LAPI ownership keys differ
