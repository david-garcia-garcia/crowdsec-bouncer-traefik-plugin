## MODIFIED Requirements

### Requirement: Captcha siteverify Timeout is the effective captcha seconds
When an owning middleware constructs the captcha provider `http.Client`, that client’s `Timeout` SHALL be `config.CaptchaSiteverifyHTTPTimeoutSeconds` seconds. It MUST NOT read a shared or inherited timeout. Subscribers SHALL use the published client and MUST NOT construct a second siteverify client from leftover keys. `pkg/captcha` SHALL keep local parameter names (`siteKey`, `secretKey`, `gateSecret`); the owner SHALL pass `CaptchaSiteKey` into those arguments and MUST NOT grow a `bouncer` field on captcha.

#### Scenario: Captcha knob sets siteverify Timeout
- **WHEN** a captcha owner Opens with a captcha provider set and `CaptchaSiteverifyHTTPTimeoutSeconds` 1
- **THEN** the stored captcha siteverify `http.Client` Timeout is 1 second

#### Scenario: Captcha omit uses the captcha default
- **WHEN** a captcha owner Opens with a captcha provider set and the captcha timeout omitted
- **THEN** the stored captcha siteverify `http.Client` Timeout is 10 seconds

#### Scenario: Two subscribers share one siteverify client
- **WHEN** two bouncing middlewares subscribe to the same published captcha instance
- **THEN** both use that instance's siteverify `http.Client`
- **AND** neither constructs a local captcha client

### Requirement: Captcha verdict without a published client is a ban
When the remediation kind is captcha and the loaded captcha binding is empty or not valid, the bouncer SHALL remediate as a ban. It MUST NOT construct a fallback local captcha client on the request path or in `bouncer.New`. A bounce-only middleware MUST NOT build a captcha client from leftover `captcha*` owner-read keys.

#### Scenario: Unpublished captcha with startup block off bans
- **WHEN** the bouncer subscribed to captcha, `bouncerStartupBlock` is false, the loaded captcha value is empty, and the verdict is captcha
- **THEN** the response is a ban
- **AND** no captcha challenge page is served

#### Scenario: Bounce-only leftover keys are not a client
- **WHEN** `captchaEnabled` is false, `captchaProvider` is set on this router, and no captcha client is published
- **THEN** `bouncer.New` does not construct a captcha client from those keys
- **AND** a captcha verdict remediates as a ban when startup block is false
