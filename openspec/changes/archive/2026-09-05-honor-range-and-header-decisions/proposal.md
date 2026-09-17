## Why

On `master` this plugin remediates only by exact client IP. CrowdSec already issues Range, Country, AS, and other scoped decisions; stream cache keys `decision.Value` and ServeHTTP looks up only `remoteIP`, so those decisions never match. Upstream [PR 383](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/383) solved that against `main` (closes [#271](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/271); supersedes [PR 368](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/368)). This fork needs the same matching on `master`'s split packages, plus real-stack e2e now that that suite exists.

## What Changes

- Honor CrowdSec `Range` decisions by CIDR containment in stream/alone (live/none already expand Range via LAPI `?ip=`).
- Add public config `decisionScopeHeaders` (scope name → request header). Empty disables header scopes. `Ip` and `Range` cannot be keys.
- Match Country, AS, and any other mapped scope from those headers. This plugin does not geolocate.
- When several scopes hit, ban wins over captcha.
- Use in-tree SimpleRedis `MGet` for the multi-key lookup (do not keep 383's looped GET).
- Real-stack Pester coverage for Range and a header-mapped Country via geoblock enrich (public IP). Keep a mock `scope-headers` scenario for fast CI (synthetic headers).
- README documents the new key. `examples/geoenrich-decisions` chains geoblock enrich then the bouncer.

## Capabilities

### New Capabilities

- `core_plugin_decisions_scopes`: Match CrowdSec decisions by Ip, Range, and header-mapped scopes using `GetRemoteIP` and configured request headers.

### Modified Capabilities

- `build_e2e_pester_crowdsec-stack`: Real-stack Pester MUST cover Range CIDR containment and at least one header-mapped scope against live Crowdsec.

## Impact

- `pkg/bouncer/bouncer.go` lookup, `pkg/crowdsecconnection/connection.go` stream/live, `pkg/configuration` `decisionScopeHeaders`, `pkg/cache` `GetMany` via `MGet`, new `pkg/decisionscope`, `pkg/ip.InNetwork`.
- `tests/e2e/real/` (Pester + TestUtils + file-provider chain with traefik-geoblock) and `tests/e2e/mock/scenarios/scope-headers/`.
- `examples/geoenrich-decisions`. README public key. Redis logical keys grow (`scope:value`, `range-index`) but stay prefixed by connection identity.
- No GeoIP. No radix tree. Do not merge [PR 368](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/368).
