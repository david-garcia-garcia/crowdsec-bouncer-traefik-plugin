## 1. pkg/appsec

- [x] 1.1 Add `pkg/appsec` with `Client`, `Query`, envelope types, `Prepare`, `New`, `Open`, reclaim key, `Close`
- [x] 1.2 Move AppSec unit tests and `NewTestClient` into `pkg/appsec`
- [x] 1.3 Copy `closeIdle` / `isReverseProxyError`; do not import `pkg/lapi`

## 2. pkg/lapi

- [x] 2.1 Rename `pkg/crowdsecconnection` → `pkg/lapi`; type `Client`; drop AppSec fields, client, and `AppsecQuery`
- [x] 2.2 Drop AppSec from live identity and stream settings; reclaim prefixes `lapi:` / `lapi:stream:`
- [x] 2.3 Keep `Prepare` for LAPI/CAPI/Redis secrets only

## 3. Plugin + bouncer

- [x] 3.1 `plugin.go`: `lapi.Prepare` then `appsec.Prepare`; OpenStream/OpenLive vs skip LAPI on `appsec` mode; `appsec.Open` when enabled
- [x] 3.2 Bouncer holds `lapiClient *lapi.Client` and `appsecClient *appsec.Client`; `Query` on pass path; store `crowdsecMode` on Bouncer
- [x] 3.3 Update `.golangci.yml` depguard and path excludes

## 4. Tests and callers

- [x] 4.1 Update `plugin_test.go`, `pkg/bouncer` tests, and any remaining `crowdsecconnection` imports
- [x] 4.2 `go test` packages that imported the old path; set localTests from that run
