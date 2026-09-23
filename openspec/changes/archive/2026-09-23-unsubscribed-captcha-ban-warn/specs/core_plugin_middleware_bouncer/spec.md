## ADDED Requirements

### Requirement: Unsubscribed captcha kind warns then bans
When the remediation kind is captcha and this bouncer did not subscribe to captcha, the bouncer SHALL emit WARN `crowdsec bouncer captcha unsubscribed` with attributes `leg` equal to `captcha` and `instanceName` (empty when unsubscribed) on every remediating request that reaches that path, then remediate as a ban. It MUST NOT emit an `ip` attribute on that WARN. It MUST NOT reconstruct the client address; identity stays `pkg/ip.GetRemoteIP` on `clientRequest`. It MUST NOT emit this WARN when the bouncer subscribed to captcha, including when the loaded captcha binding is empty or not valid. Subscribed-unpublished with `bouncerStartupBlock` true SHALL stay HTTP 503 plus WARN `crowdsec bouncer backend missing`. This WARN SHALL apply to every captcha-kind remediation that reaches the remediating handler (LAPI captcha kind, forced header `c`, captcha failure-action).

#### Scenario: Bounce-only captcha kind warns then bans
- **WHEN** the bouncer did not subscribe to captcha
- **AND** the remediation kind is captcha
- **THEN** the response is a ban
- **AND** the log contains WARN `crowdsec bouncer captcha unsubscribed` with `leg` `captcha` and empty `instanceName`
- **AND** that record MUST NOT include `ip`

#### Scenario: Forced captcha header on an unsubscribed router warns then bans
- **WHEN** the bouncer did not subscribe to captcha
- **AND** `bouncerDecisionHeader` forces `c`
- **AND** lookup is not a ban
- **THEN** the response is a ban
- **AND** the log contains WARN `crowdsec bouncer captcha unsubscribed`

#### Scenario: Two remediating requests warn twice
- **WHEN** the bouncer did not subscribe to captcha
- **AND** two requests receive captcha kind
- **THEN** WARN `crowdsec bouncer captcha unsubscribed` is emitted twice

#### Scenario: Subscribed unpublished does not emit this warn
- **WHEN** the bouncer subscribed to captcha
- **AND** `bouncerStartupBlock` is false
- **AND** the loaded captcha value is empty
- **AND** the verdict is captcha
- **THEN** the response is a ban
- **AND** the log MUST NOT contain `crowdsec bouncer captcha unsubscribed`

#### Scenario: Subscribed unpublished startup block stays backend missing
- **WHEN** the bouncer subscribed to captcha
- **AND** `bouncerStartupBlock` is true
- **AND** captcha is not published
- **THEN** every request returns 503
- **AND** the log contains WARN `crowdsec bouncer backend missing`
- **AND** the log MUST NOT contain `crowdsec bouncer captcha unsubscribed`
