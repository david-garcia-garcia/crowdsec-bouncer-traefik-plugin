## 1. Vendor published backendbackoff

- [x] 1.1 Import `github.com/david-garcia-garcia/traefik-middleware-utilities/backendbackoff` and run `go mod vendor` (stay on `v1.0.3`; do not bump)
- [x] 1.2 Confirm `vendor/modules.txt` lists `backendbackoff` and that `pkg/` has no copy, no `pkg/health`, and no traefik-modsecurity import

## 2. Shared knobs and validation

- [x] 2.1 Add the six `backendBackoff*` fields on `configuration.Config` with CreateConfig defaults matching package defaults
- [x] 2.2 Add `BackendBackoffConfig()` that maps seconds to `time.Duration`
- [x] 2.3 `ValidateParams` calls `backendbackoff.New` then `Close` and rejects what New rejects (every `crowdsecMode`)
- [x] 2.4 Document the keys and defaults in README next to `HTTPTimeoutSeconds`
- [x] 2.5 Tests: omit uses defaults; `FailureRatio` `1.5` and `MaxCooldown` `<` `BaseCooldown` fail; `Jitter` `0` is accepted; `New` returns nil handler without opening LAPI

## 3. Live/none LAPI Gate

- [x] 3.1 Construct a Gate in live/none `lapi.New` from `BackendBackoffConfig()`; stream/alone leave nil
- [x] 3.2 Thread inbound request context into `LiveLookup` and down to each `queryLiveDecisions` GET
- [x] 3.3 Allow on the URL stem (no query) before each GET; Debug-log wait; do not sleep; distinct skip error
- [x] 3.4 Report after an admitted GET (success = remediation value; failure = query/HTTP/parse/duration-parse)
- [x] 3.5 Close the Gate from `lapi.Client.Close` (nil-check)
- [x] 3.6 `pkg/bouncer` passes `req.Request.Context()`; update existing `LiveLookup` call sites
- [x] 3.7 Tests: after enough failures the next `LiveLookup` does not hit the test server and still applies FailureAction; a success Report recovers; a later scope GET also skips; stream polls stay on `UpdateMaxFailure` (no Allow)

## 4. AppSec Gate

- [x] 4.1 Construct a Gate in `appsec.New` from `BackendBackoffConfig()`
- [x] 4.2 Allow on the AppSec URL stem before each `Do`; Debug-log wait; do not sleep; distinct skip error into `resultForFailureAction`
- [x] 4.3 Inbound unreadable-body drop: no Allow, no Report
- [x] 4.4 Report after an admitted Do (failure = Do error / 502/503/504 / 500; success includes `errAppsecReadBody`)
- [x] 4.5 Close the Gate from `appsec.Client.Close`
- [x] 4.6 Tests: after enough failures the next `Query` does not hit the test server and still applies FailureAction; a success Report recovers; unreadable-body ban never Allows

## 5. Verify

- [x] 5.1 `go build ./...`, `go vet ./...`, `go test ./pkg/... -count=1`, `go test . -count=1`, `golangci-lint run ./...`
