## 1. pkg/appsec

- [ ] 1.1 Add `pkg/appsec` with `Client`, `Query`, envelope types, `Prepare`, `New`, `Open`, reclaim key, `Close`
- [ ] 1.2 Move AppSec unit tests and `NewTestClient` into `pkg/appsec`
- [ ] 1.3 Copy `closeIdle` / `isReverseProxyError`; do not import `pkg/lapi`

## 2. pkg/lapi

- [ ] 2.1 Rename `pkg/crowdsecconnection` → `pkg/lapi`; type `Connection`; drop AppSec fields, client, and `AppsecQuery`
- [ ] 2.2 Drop AppSec from live identity and stream settings; reclaim prefixes `lapi:` / `lapi:stream:`
- [ ] 2.3 Keep `Prepare` for LAPI/CAPI/Redis secrets only

## 3. Plugin + bouncer

- [ ] 3.1 `plugin.go`: `lapi.Prepare` then `appsec.Prepare`; OpenStream/OpenLive vs skip LAPI on `appsec` mode; `appsec.Open` when enabled
- [ ] 3.2 Bouncer holds `*lapi.Connection` and `*appsec.Client`; `Query` on pass path; store `crowdsecMode` on Bouncer
- [ ] 3.3 Update `.golangci.yml` depguard and path excludes

## 4. Tests and callers

- [ ] 4.1 Update `plugin_test.go`, `pkg/bouncer` tests, and any remaining `crowdsecconnection` imports
- [ ] 4.2 `go test` packages that imported the old path; set localTests from that run
