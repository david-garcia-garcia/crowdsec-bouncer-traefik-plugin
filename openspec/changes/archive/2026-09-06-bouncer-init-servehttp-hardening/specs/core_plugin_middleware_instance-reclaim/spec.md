## MODIFIED Requirements

### Requirement: Bouncer does not own the stream
The per-router bouncer SHALL handle request policy (trusted IPs, ban/captcha pages, whether AppSec runs on pass) and MUST NOT start a process-wide stream ticker. The bouncer SHALL hold a `*lapi.Client` (nil when `crowdsecMode` is `appsec`) and a `*appsec.Client` (nil when AppSec is off). `Bouncer.New` SHALL return an error when trusted-IP checker construction or ban template loading fails instead of starting with nil checkers or an empty ban body.

#### Scenario: New fails on bad trusted IP CIDR
- **WHEN** `Bouncer.New` is called with an invalid forwarded-headers trusted IP CIDR
- **THEN** construction returns an error

#### Scenario: New fails on missing ban template
- **WHEN** `Bouncer.New` is called with a `BanFilePath` that cannot be loaded
- **THEN** construction returns an error
