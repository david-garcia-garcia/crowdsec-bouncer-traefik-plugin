## 1. Reclaim copy

- [x] 1.1 Copy `pkg/reclaim` (table, default, tests) from traefik-geoblock into this module; stdlib-only table file
- [x] 1.2 Confirm package `Open` / `Default` / `ResetWith` compile in this module

## 2. Isolated cache

- [x] 2.1 Remove the process-wide `ttl_map`; give each memory Client its own map
- [x] 2.2 Prefix Redis GET/SET/DEL keys with connection identity
- [x] 2.3 Tests: two memory Clients do not leak; two Redis prefixes do not leak; stream lease is per Client

## 3. CrowdsecConnection

- [x] 3.1 Add `pkg/crowdsecconnection` owning stream ticker, metrics ticker, isolated cache Client, LAPI/CAPI HTTP, AppSec HTTP client
- [x] 3.2 `Close()` stops tickers and idle HTTP; connection key hashes connection fields only
- [x] 3.3 Tests: two different LAPI configs are two incarnations; same fields share one pointer

## 4. Bouncer + Yaegi root

- [x] 4.1 Move request handling into `pkg/bouncer` (`ForRoute`); captcha and templates stay here; GetRemoteIP stays `pkg/ip`
- [x] 4.2 Root package exports only `CreateConfig` / `New`; `New` uses constructor ctx with `reclaim.Open` then `bouncer.ForRoute`
- [x] 4.3 Delete process globals (`streamTicker`, `isCrowdsecStreamHealthy`, first-wins)

## 5. Unit tests (two configs)

- [x] 5.1 Two httptest LAPIs, two `New` in one process: ban on A is allow on B
- [x] 5.2 Reclaim grace/reclaim/dispose for Connection (`reclaim.ResetWith` in cleanup)
- [x] 5.3 ServeHTTP matrix (stream vs live, captcha, trusted IPs, AppSec on pass) against isolated connections
- [x] 5.4 Fill empty `TestNew` / stream / query tables so they fail if first-wins remains

## 6. Mock e2e dual-bouncer

- [x] 6.1 Scenario: one Traefik, two middleware names, two LAPI mocks, two routers
- [x] 6.2 Assert ban-on-A / allow-on-B; fail if both routers share one cache or one LAPI
