# Standards

1. [hard] Leave a trail — `pkg/lapi/client_http.go:89` — new `crowdsecQueryWithMethod` has no succinct job comment (commandment: every method SHALL have at least one comment that says what it does)
   → Add a one-line comment describing LAPI round-trip with explicit method and POST body replay on alone-mode 401
   Status: done
   Argument: added method comment on crowdsecQueryWithMethod.

2. [judgement] Duplicated Code — `pkg/lapi/client_http.go:79-86` — `crowdsecQuery` selects GET vs POST then delegates to `crowdsecQueryWithMethod`; split is justified for 401 retry but adds a hop
   → Acceptable; retry path needs stable method and body bytes
   Status: skipped
   Argument: judgement; split required for alone-mode POST replay.
