## 1. Config and IP helper

- [x] 1.1 Add `decisionScopeHeaders` to `pkg/configuration.Config`, default empty, reject `Ip`/`Range` keys
- [x] 1.2 Add `ip.InNetwork` for one CIDR or bare IP

## 2. Decision-scope package

- [x] 2.1 Add `pkg/decisionscope` (normalize, header keys, range-index add/remove/match, ban-over-captcha)
- [x] 2.2 Unit tests: Country/AS normalize, skip missing header, Range containment, ban wins overlap

## 3. Cache GetMany

- [x] 3.1 Add `Client.GetMany` using in-tree `MGet` on Redis (prefixed keys, one `nextReader`) and looped get on memory
- [x] 3.2 Tests: missing keys omitted; unreachable fails the batch

## 4. Stream and live

- [x] 4.1 Stream: Ip keys via `ipCacheKey`; Range onto `range-index`; header scopes as `scope:value`; `scopes=` query includes mapped scopes; CAPI omits `scopes`
- [x] 4.2 Live/none: keep `?ip=`; add `scope`+`value` when a mapped header is present; skip `range-index` on that path

## 5. Request lookup

- [x] 5.1 ServeHTTP uses `GetRemoteIP`, then `GetMany` for IP, header-scope keys, and `range-index`; ban wins; missing header skips that scope
- [x] 5.2 Pass `decisionScopeHeaders` from config into bouncer and connection

## 6. Mock e2e

- [x] 6.1 Add `tests/e2e/mock/scenarios/scope-headers/` from 383 (Country, AS, username, Range)

## 7. Real-stack e2e

- [x] 7.1 Extend `TestUtils` with `--range` / `--scope` `--value` injectors and extra request headers
- [x] 7.2 Dedicated compose middleware with `decisionScopeHeaders`; Pester for Range (stream + none) and a header-mapped Country (or custom) scope

## 8. Docs

- [x] 8.1 README: `decisionScopeHeaders` examples, no GeoIP, header trust warning
