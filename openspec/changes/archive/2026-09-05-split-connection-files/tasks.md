## 1. AppSec file

- [x] 1.1 Move AppSec constants, `AppsecPolicy`, `AppsecResponse`, `AppsecAction*`, `ErrFailureCaptcha`, `AppsecQuery`, and AppSec helpers into `connection_appsec.go`
- [x] 1.2 Leave `appsec_test.go` and `test_appsec_connection.go` in the same package

## 2. Stream file

- [x] 2.1 Move `startStream`, `handleStreamTicker`, `handleStreamCache`, `Stream` type, and `cacheTimeoutKey` into `connection_stream.go`
- [x] 2.2 Keep `startTicker`/`stopTicker` in `connection.go`

## 3. Live file

- [x] 3.1 Move `LiveLookup` and `handleNoStreamCache` into `connection_live.go`
- [x] 3.2 Leave `queryLiveDecisions` and live cache helpers in `connection_decisions.go`

## 4. HTTP file

- [x] 4.1 Move LAPI/CAPI route/header constants, `Login`, `getToken`, `crowdsecQuery`, `isReverseProxyError`, and `closeIdle` into `connection_http.go`

## 5. Metrics file

- [x] 5.1 Move `handleMetricsTicker`, `reportMetrics`, and the metrics route constant into `connection_metrics.go`

## 6. Verify

- [x] 6.1 `go test ./pkg/crowdsecconnection/ ./pkg/bouncer/`
- [x] 6.2 Confirm exported identifiers still resolve from `plugin.go` and `pkg/bouncer` with no import-path change
