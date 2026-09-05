## 1. In-tree SimpleRedis (PR #8)

- [x] 1.1 Copy `simpleredis.go`, tests, and Apache-2.0 LICENSE from `maxlerebourg/simpleredis@f8801cc` (`pool-redis-connections`) into `pkg/simpleredis`
- [x] 1.2 Point `pkg/cache` at the in-tree import; store `writer` and `readers` as `*simpleredis.SimpleRedis`; update `cache_test.go` round-robin helpers
- [x] 1.3 Remove `github.com/maxlerebourg/simpleredis` from `go.mod`, `vendor/`, and `.golangci.yml` depguard (allow the in-tree path)

## 2. Mock e2e RESP

- [x] 2.1 Update `tests/e2e/mock/mocklapi/main.go` `serveRedis` to parse RESP arrays while still accepting inline `GET `
- [x] 2.2 Keep replica/primary hit-miss mapping for `1.2.3.4` / `1.2.3.5`

## 3. Dragonfly real-stack e2e

- [x] 3.1 Add Dragonfly `docker.dragonflydb.io/dragonflydb/dragonfly:v1.40.2` to `tests/e2e/real/docker-compose.test.yml` (6379, memlock -1)
- [x] 3.2 Add a live-mode whoami route with `redisCacheEnabled` and `redisCacheHost` pointing at Dragonfly; Traefik `depends_on` Dragonfly
- [x] 3.3 Add `tests/e2e/real/*.Tests.ps1` for live-mode TTL against Dragonfly and cached-ban after Traefik restart; client identity only `X-Forwarded-For`

## 4. Specs allowlist and verify

- [x] 4.1 Add `core` / `cache` to `openspec/specs/domains.md`
- [x] 4.2 Run `go test ./...`, `make yaegi_test` if Yaegi is installed, and set `localTests` from the result
