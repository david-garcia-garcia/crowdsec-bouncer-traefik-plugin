## 1. Forward HTTP version

- [ ] 1.1 Add `crowdsecAppsecHTTPVersionHeader` (`X-Crowdsec-Appsec-Http-Version`) next to the other CrowdSec header constants in `pkg/appsec/query.go`
- [ ] 1.2 In `newAppsecForwardRequest`, when `req.ProtoMajor` is greater than 0, set that header to `fmt.Sprintf("%d%d", req.ProtoMajor, req.ProtoMinor)`. Omit the header when `ProtoMajor` is 0. Read `req.ProtoMajor` / `req.ProtoMinor`. Do not parse `req.Proto`. Do not snapshot proto on `clientrequest.New`. Do not copy upstream `appsecQuery` verbatim. Do not change the other `X-Crowdsec-Appsec-*` headers

## 2. Prove the header

- [ ] 2.1 In `pkg/appsec/zzz_query_test.go`, add a `Query` test through `newForwardCaptureClient` / `forwardCaptureRoundTripper` that asserts HTTP/1.1 → `11`, HTTP/2 → `20`, HTTP/3 → `30`, and `ProtoMajor` 0 → header absent

## 3. Usage packet

- [ ] 3.1 Update `knowledge/devdocs/core_plugin_appsec.md` How-to-use Query header bullets: set `X-Crowdsec-Appsec-Http-Version` from inbound `ProtoMajor` / `ProtoMinor` as two ASCII digits; omit when `ProtoMajor` is 0. Do not add a Language term

## 4. Verify

- [ ] 4.1 `go test ./pkg/appsec/` and `golangci-lint run ./pkg/appsec/...`
