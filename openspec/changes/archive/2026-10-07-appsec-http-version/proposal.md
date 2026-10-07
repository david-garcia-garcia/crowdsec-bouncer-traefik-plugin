## Why

CrowdSec AppSec expects the original client HTTP version on `X-Crowdsec-Appsec-Http-Version` as two ASCII digits (`10`, `11`, `20`, …) so it can populate `r.Proto`. This plugin never sends that header, so AppSec evaluates rules against the Traefik-to-AppSec connection version (HTTP/1.1) instead of the client protocol.

## What Changes

- Set `X-Crowdsec-Appsec-Http-Version` in `newAppsecForwardRequest` beside the other CrowdSec headers. Do not copy upstream `appsecQuery` verbatim.
- Encode as two ASCII digits, major then minor (`fmt.Sprintf("%d%d", ProtoMajor, ProtoMinor)`). Owner is inbound `req.ProtoMajor` / `req.ProtoMinor`. Do not snapshot a parallel field on `clientrequest.New`.
- Omit the header when `ProtoMajor` is 0 so AppSec keeps the listener connection proto instead of applying `"00"`.
- HTTP/3 encodes as `"30"` through the same sprintf.
- Add a unit test in `pkg/appsec/zzz_query_test.go` that the outbound AppSec request carries the header.
- **Not BREAKING.** No public Traefik config keys. Other `X-Crowdsec-Appsec-*` headers stay as they are.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_appsec_client`: `Query` SHALL set `X-Crowdsec-Appsec-Http-Version` from inbound `ProtoMajor` / `ProtoMinor` as two ASCII digits and SHALL omit it when `ProtoMajor` is 0.

## Impact

- `pkg/appsec/query.go` (`newAppsecForwardRequest` CrowdSec header block)
- `pkg/appsec/zzz_query_test.go` (forward-capture assertion)
- Live spec `openspec/specs/core_plugin_appsec_client/` (delta in this change)
- Usage packet `knowledge/devdocs/core_plugin_appsec.md` How-to-use list (implement adds the header to the existing Query header bullets)
- Upstream report: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/400
