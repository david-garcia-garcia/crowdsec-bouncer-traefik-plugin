## 1. Narrow AppSec reclaim key

- [ ] 1.1 Drop `HTTPTimeoutSeconds` and the three AppSec TLS content fields from `identity` / `identityFrom` / `IdentityHex` / `Key`
- [ ] 1.2 Keep scheme, host, path, key, and `bodyLimit` on that identity
- [ ] 1.3 Leave `crowdsecAppsecFailureAction` off the key (already on Bouncer + `Policy`)

## 2. Transport on atomic.Value

- [ ] 2.1 Extract unexported `transport` in `pkg/appsec/client_http.go` (HTTP client, API key, timeout, AppSec TLS extras)
- [ ] 2.2 Store it on `Client` as `atomic.Value` with the Yaegi v0.16 comment; delete write-once `httpClient` and `appsecKey`; `Query` / `Close` read `currentTransport()`
- [ ] 2.3 Add `AdoptTransport(cfg)` after `Open` bind: Store new, `closeIdle` old
- [ ] 2.4 Do not use `atomic.Pointer[T]`; do not make remaining write-once Client scalars mutable

## 3. Logging

- [ ] 3.1 INFO `appsec transport replaced` with reclaim `Key` when timeout or TLS extras change
- [ ] 3.2 Leave `reclaim_put` / `reclaim_reclaim` / `reclaim_dispose` at DEBUG

## 4. Tests

- [ ] 4.1 Same Client after a TLS-only reload
- [ ] 4.2 Same Client after an `HTTPTimeoutSeconds`-only reload
- [ ] 4.3 Different AppSec hosts still isolate Clients
- [ ] 4.4 Body-limit change still opens a new Client
- [ ] 4.5 Existing same-config reclaim test still passes

## 5. Debt and verify

- [ ] 5.1 Delete `knowledge/debt/2026-09-17-appsec-captcha-split.md` and close the row on this run’s `issues.md`
- [ ] 5.2 `go test` for `pkg/appsec` (and `pkg/bouncer` only if that package was touched)
- [ ] 5.3 Grep live product paths (not `openspec/changes/archive/`, not `devstate/`) for `atomic.Pointer` in `pkg/appsec/`
