## MODIFIED Requirements

### Requirement: Real stack covers the Redis rate limit
The real-stack Pester suite SHALL run the rate-limit leg inside Traefik's plugin loader against the stack's Dragonfly service, configured through the file provider (the bucket list is a list of objects with nested lists, which Docker labels do not decode). It SHALL prove: a `ratelimit` bucket answers `rateLimitStatusCode` with `Retry-After` and remediation header `ban:ratelimit:<bucket>` after `requests` hits; a different client address is not limited by that counter; a `bypassRateLimit` action rule lets the over-limit client through; a `log` bucket never answers; an unreachable Redis with `rateLimitFailureAction: passthrough` lets the request through and with `ban` answers `ban:ratelimit-failure`; a `ratelimit` answer reaches `cscli metrics` as a drop with origin `plugin:ratelimit:<bucket>`; and an owner with `rateLimitAlgorithm: tokenBucket` admits `burst` requests at once, answers the next with 429 and a `Retry-After` equal to the refill time of one token, and admits again after that time. Each case SHALL use a client address no other case uses, so counters left in Dragonfly by an earlier run or case cannot change the result. The file SHALL be listed in one CI Pester domain.

#### Scenario: Deny after the limit on real Traefik
- **WHEN** a client sends `requests + 1` requests to a route whose `ratelimit` bucket allows `requests` per window
- **THEN** the last response is 429 with `Retry-After` equal to the counter's next admit (for 4 hits on a limit of 3 per minute: the time to the window end plus 30s, within 1s)
- **AND** the remediation header is `ban:ratelimit:<bucket>`

#### Scenario: Token bucket burst and refill on real Traefik
- **WHEN** a client sends `burst + 1` requests at once to a route whose owner sets `rateLimitAlgorithm: tokenBucket` and whose `ratelimit` bucket has `burst` 3, `requests: 1`, and `window: 5s`
- **THEN** the first 3 responses come from the backend
- **AND** the fourth is 429 with `Retry-After: 5` and remediation header `ban:ratelimit:<bucket>`
- **AND** after `Retry-After` seconds the next request from that client reaches the backend

#### Scenario: Redis down with passthrough
- **WHEN** the middleware points `rateLimitRedisHost` at a port where nothing listens and `rateLimitFailureAction` is `passthrough`
- **THEN** requests reach the backend

#### Scenario: Deny is a drop in cscli
- **WHEN** a `ratelimit` answer happens on a router with a LAPI client and a short metrics interval
- **THEN** `cscli metrics` for that bouncer shows a dropped count under origin `plugin:ratelimit:<bucket>`

## ADDED Requirements

### Requirement: Real stack covers the shared rate-limit leg
The real-stack Pester suite SHALL run one rate-limit owner without `bouncerEnabled` and two subscribing middlewares on separate routers against Dragonfly, through the file provider. It SHALL prove one policy for both subscribers, a separate budget per subscriber, severance when the owner is removed and rebinding when it returns, and that an owner bucket edit binds a new client without resetting counters. Each case SHALL use its own client address.

#### Scenario: One policy on both subscribers
- **WHEN** a client sends `requests + 1` requests through subscriber A and another client does the same through subscriber B
- **THEN** both last responses carry the owner's `rateLimitStatusCode` and `ban:ratelimit:<bucket>`

#### Scenario: Separate budgets per subscriber
- **WHEN** a client exhausts the bucket through subscriber A
- **THEN** the same client's next `requests` requests through subscriber B reach the backend

#### Scenario: Owner removed, then restored
- **WHEN** the dynamic file drops the owner and the reclaim grace passes
- **THEN** subscribers pass requests through without a remediation header
- **AND** Traefik logs `crowdsec bouncer unbound` with `"leg":"ratelimit"`
- **AND** each subscriber logs WARN `crowdsec bouncer rate limit owner unavailable` once for that removal
- **AND** when the owner is added back, the logs show `crowdsec bouncer bound` with `"leg":"ratelimit"` and an over-limit client is answered again
- **AND** each subscriber logs INFO `crowdsec bouncer rate limit owner available` once and no WARN, whether Traefik rebuilt it before or after the owner

#### Scenario: Bucket edit keeps the count
- **WHEN** a client sends `requests` requests through a subscriber, then the owner's bucket is raised to `requests + 2`
- **THEN** Traefik logs `crowdsec ratelimit instance started` with a new incarnation
- **AND** that client's next 2 requests reach the backend and the third is answered by the bucket

### Requirement: Real stack covers captcha buckets
The real-stack Pester suite SHALL run a subscriber that also subscribes to the stack's custom-provider test captcha, with a `captcha` bucket stacked on a `ratelimit` bucket on the same key. It SHALL prove the challenge, that a solved client skips the `captcha` bucket but meets the `ratelimit` ceiling, that the captcha page's own requests are not charged, and that a `bypassCaptcha` route and a router without a captcha get the `ratelimit` answer. Each case SHALL use its own client address.

#### Scenario: Challenge, solve, hard limit
- **WHEN** a client passes the `captcha` bucket's limit
- **THEN** it gets the challenge page with `captcha:ratelimit:<soft bucket>`
- **AND** after it solves the challenge its requests reach the backend until the `ratelimit` bucket answers with 429 and `ban:ratelimit:<hard bucket>`

#### Scenario: Verification POST is not charged
- **WHEN** a client over both limits posts the challenge form with the marker
- **THEN** the response is not a rate-limit answer

#### Scenario: Marker POST no gate answers is charged
- **WHEN** a client posts a form with the marker on a route with a usable captcha whose policy has no captcha answer, or where a `bypassCaptcha` rule matches
- **THEN** each POST is charged and the client reaches the `ratelimit` answer with `ban:ratelimit:<bucket>`

#### Scenario: bypassCaptcha route gets a 429
- **WHEN** a `bypassCaptcha` rule matches and the `captcha` bucket is over its limit
- **THEN** the response is 429 with `ban:ratelimit:<soft bucket>`

#### Scenario: Router without a captcha gets a 429
- **WHEN** a subscriber without a captcha instance name passes the `captcha` bucket's limit
- **THEN** the response is 429 with `ban:ratelimit:<soft bucket>`
- **AND** Traefik logs ERROR `crowdsec bouncer rate limit captcha unavailable` once for that router
