## ADDED Requirements

### Requirement: Captcha siteverify Timeout is the effective captcha seconds
When `bouncer.New` constructs the captcha provider `http.Client`, that client’s `Timeout` SHALL be `config.EffectiveHTTPTimeoutSeconds(config.CaptchaSiteverifyHTTPTimeoutSeconds)` seconds. It MUST NOT read raw `HTTPTimeoutSeconds` when the captcha override is non-zero. The client SHALL stay per-Bouncer. Implementations MUST NOT reclaim a captcha HTTP client and MUST NOT add `sync.Once` or a package-global siteverify client.

#### Scenario: Captcha override sets siteverify Timeout
- **WHEN** `bouncer.New` runs with a captcha provider set, `HTTPTimeoutSeconds` 10, and `CaptchaSiteverifyHTTPTimeoutSeconds` 1
- **THEN** the stored captcha siteverify `http.Client` Timeout is 1 second

#### Scenario: Captcha omit inherits the shared default
- **WHEN** `bouncer.New` runs with a captcha provider set, `HTTPTimeoutSeconds` 10, and `CaptchaSiteverifyHTTPTimeoutSeconds` 0
- **THEN** the stored captcha siteverify `http.Client` Timeout is 10 seconds
