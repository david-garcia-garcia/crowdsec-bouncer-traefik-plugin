## 1. Stream poll serialization

- [x] 1.1 Add dedicated stream poll gate on `lapi.Client` (mutex or in-flight flag); do not reuse `Client.mu` for poll body
- [x] 1.2 Wrap `handleStreamTicker` / `handleStreamCache` entry so `startStream`, `startTicker`, and `Wake` cannot overlap polls
- [x] 1.3 Update health field mutations (`updateFailure`, healthy/startup flags) only inside the serialized poll path
- [x] 1.4 Fix lease short-circuit on `updated`: skip GET only when no poll in flight; do not mask in-flight failure as success

## 2. LAPI HTTP helper

- [x] 2.1 Split `crowdsecQuery` transport check: return unreachable when `err != nil || res == nil` before reading status
- [x] 2.2 Buffer POST body bytes before first `Do`; on alone-mode 401 renew token and retry with same method and body
- [x] 2.3 Confirm stream/live GET 401 paths remain single-attempt (no new retry)

## 3. Live scope error propagation

- [x] 3.1 `mergeLiveScope`: return error when scope `queryLiveDecisions` fails (stop fail-open log-and-continue)
- [x] 3.2 `handleNoStreamCache`: propagate scope error as `("", err)` like IP unreachable

## 4. httptest coverage

- [x] 4.1 Stream health: `updateMaxFailure` 0 marks unhealthy on failed poll; `-1` stays healthy; recovery on success (direct `handleStreamTicker` / `handleStreamCache` calls)
- [x] 4.2 Stream JSON apply: IP ban, header scope, range add, delete paths update cache/range index
- [x] 4.3 Transport: custom `RoundTripper` returning `(nil, err)` — no panic, unreachable error
- [x] 4.4 Alone 401 POST retry: metrics POST body replay after token renewal (httptest 401 then 200)
- [x] 4.5 Live scope error: scope LAPI 500 returns error from `LiveLookup` for failure-action path

## 5. Validate

- [x] 5.1 `go test ./pkg/lapi/ -count=1`
- [x] 5.2 `openspec validate lapi-client-correctness --strict`
